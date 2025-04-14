import boto3
import json
from datetime import datetime, timedelta, timezone

# --- 설정값 ---
TARGET_SERVICES = {
    "s3.amazonaws.com": "S3",
    "ecr.amazonaws.com": "ECR",
}
ENDPOINT_MISSING_THRESHOLD = 5

# --- Boto3 클라이언트 캐싱 ---
_ec2_clients = {}
_cloudtrail_clients = {}


def get_ec2_client(region):
    if region not in _ec2_clients:
        try:
            _ec2_clients[region] = boto3.client("ec2", region_name=region)
            _ec2_clients[region].describe_regions(RegionNames=[region])
        except Exception as e:
            print(f"오류: 리전 '{region}' EC2 클라이언트 생성 실패: {e}")
            return None
    return _ec2_clients[region]


def get_cloudtrail_client(region):
    if region not in _cloudtrail_clients:
        try:
            _cloudtrail_clients[region] = boto3.client("cloudtrail", region_name=region)
        except Exception as e:
            print(f"오류: 리전 '{region}' CloudTrail 클라이언트 생성 실패: {e}")
            return None
    return _cloudtrail_clients[region]


# --- EC2 인스턴스 정보 조회 ---
def get_instance_network_details(region, instance_id):
    """주어진 인스턴스 ID로부터 VPC, 서브넷, 보안 그룹 정보를 조회"""
    print(f"인스턴스 '{instance_id}' 네트워크 정보 조회 중 (리전: {region})...")
    ec2_client = get_ec2_client(region)
    if not ec2_client:
        return None
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations")
        if not reservations or not reservations[0].get("Instances"):
            print(f"오류: 인스턴스 ID '{instance_id}'를 찾을 수 없습니다.")
            return None
        instance = reservations[0]["Instances"][0]
        vpc_id = instance.get("VpcId")
        subnet_id = instance.get(
            "SubnetId"
        )  # 단일 서브넷 ID (HA는 select_subnets_for_ha 에서 처리)
        security_groups = instance.get("SecurityGroups", [])
        security_group_ids = [
            sg.get("GroupId") for sg in security_groups if sg.get("GroupId")
        ]
        if not vpc_id or not subnet_id or not security_group_ids:
            print(
                f"오류: 인스턴스 '{instance_id}' 필수 네트워크 정보(VPC, 서브넷, SG) 누락"
            )
            return None
        return {
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,  # 참고용
            "security_group_ids": security_group_ids,
        }
    except ec2_client.exceptions.ClientError as e:
        if "InvalidInstanceID.NotFound" in str(e):
            print(f"오류: 인스턴스 ID '{instance_id}' 찾기 실패.")
        else:
            print(f"인스턴스 정보 조회 오류 ({instance_id}): {e}")
        return None
    except Exception as e:
        print(f"인스턴스 정보 조회 중 예기치 않은 오류 ({instance_id}): {e}")
        return None


# --- CloudTrail 로그 처리 ---
def lookup_service_events_and_filter_by_instance(
    region, instance_id, days=None, hours=None
):
    """특정 인스턴스 ID와 관련된 대상 서비스 이벤트를 조회하여 DataFrame 반환"""
    time_unit = "일"
    time_value = 1
    if hours is not None:
        time_unit = "시간"
        time_value = hours
        lookup_days = None
    elif days is not None:
        time_unit = "일"
        time_value = days
        lookup_days = days
    else:
        lookup_days = 1

    print(
        f"CloudTrail 이벤트 조회 중 (인스턴스 ID: {instance_id}, 최근 {time_value}{time_unit})... 리전: {region}"
    )
    client = get_cloudtrail_client(region)
    if not client:
        return []  # 오류 시 빈 리스트 반환

    records = []
    try:
        end_time = datetime.now(timezone.utc)
        start_time = (
            end_time - timedelta(hours=hours)
            if hours is not None
            else end_time - timedelta(days=lookup_days)
        )
        paginator = client.get_paginator("lookup_events")
        response_iterator = paginator.paginate(
            StartTime=start_time, EndTime=end_time, MaxResults=1000
        )

        for page in response_iterator:
            for event in page.get("Events", []):
                try:
                    cloudtrail_event = json.loads(event["CloudTrailEvent"])
                    event_source = cloudtrail_event.get("eventSource")
                    if event_source in TARGET_SERVICES:
                        user_identity = cloudtrail_event.get("userIdentity", {})
                        principal_id = user_identity.get("principalId", "")
                        if f":{instance_id}" not in principal_id:
                            continue
                        event_region = cloudtrail_event.get("awsRegion")
                        if not event_region or event_region != region:
                            continue

                        records.append(
                            {
                                "eventTime": cloudtrail_event.get("eventTime"),
                                "service": TARGET_SERVICES[event_source],
                                "eventName": cloudtrail_event.get("eventName"),
                                "vpcEndpointId": cloudtrail_event.get("vpcEndpointId"),
                                "usedVpcEndpoint": (
                                    "✅ Yes"
                                    if cloudtrail_event.get("vpcEndpointId")
                                    else "❌ No"
                                ),
                                "user": user_identity.get(
                                    "arn", user_identity.get("userName")
                                ),
                                "region": event_region,
                            }
                        )
                except Exception as e:
                    print(
                        f"경고: 이벤트 처리 중 오류 발생 (EventId: {event.get('EventId')}): {e}"
                    )
                    continue  # 개별 이벤트 오류는 계속 진행

        print(f"조회된 관련 이벤트 {len(records)}개 처리 완료.")
        return records

    except client.exceptions.InvalidTimeRangeException:
        print(
            f"오류: CloudTrail 조회 기간(최대 90일)이 잘못되었습니다. ({time_value}{time_unit})"
        )
        return []
    except Exception as e:
        print(f"CloudTrail 이벤트 조회/처리 중 오류 발생: {e}")
        return []  # 전체 오류 시 빈 리스트 반환


# --- VPC 엔드포인트 분석 ---
def analyze_endpoint_usage(events_list):
    """DataFrame 분석하여 엔드포인트 미사용 건수 반환"""
    if not events_list:
        return {}
    try:
        missing_endpoints = [
            event for event in events_list if event.get("usedVpcEndpoint") == "❌ No"
        ]
        if not missing_endpoints:
            return {}
        missing_counts = {}
        for event in missing_endpoints:
            key = (event.get("service"), event.get("region"))
            if key[0] and key[1]:  # Ensure service and region exist
                missing_counts[key] = missing_counts.get(key, 0) + 1

        # JSON 직렬화를 위해 튜플 키 대신 딕셔너리 리스트 생성
        potential_missing = [
            {"service": key[0], "region": key[1], "count": count}
            for key, count in missing_counts.items()
            if count >= ENDPOINT_MISSING_THRESHOLD
        ]
        return potential_missing
    except Exception as e:
        print(f"이벤트 데이터 분석 중 오류: {e}")
        return {}


# --- 리소스 자동 선택 ---
def select_subnets_for_ha(ec2_client, vpc_id, max_az=3):
    """HA 위한 자동 서브넷 선택"""
    print(f"VPC '{vpc_id}'에서 HA용 서브넷 자동 선택 중 (최대 {max_az}개 AZ)...")
    try:
        subnets = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["Subnets"]
        if not subnets:
            return [], "오류: 서브넷 없음"
        subnets_by_az = {}
        for sub in subnets:
            az = sub.get("AvailabilityZone")
            subnet_id = sub.get("SubnetId")
            if az and subnet_id and sub.get("State") == "available":
                if az not in subnets_by_az:
                    subnets_by_az[az] = []
                subnets_by_az[az].append(subnet_id)
        if not subnets_by_az:
            return [], "오류: 사용 가능 서브넷 없음"
        selected_subnet_ids = []
        selected_azs_info = []
        for az in sorted(subnets_by_az.keys()):
            if len(selected_subnet_ids) >= max_az:
                break
            if subnets_by_az[az]:
                selected_subnet = subnets_by_az[az][0]
                selected_subnet_ids.append(selected_subnet)
                selected_azs_info.append(f"{selected_subnet} ({az})")
        if not selected_subnet_ids:
            return [], "오류: 자동 선택 실패"
        info_text = f"✅ 자동으로 선택된 서브넷: {', '.join(selected_azs_info)}"
        print(info_text)
        return selected_subnet_ids, info_text
    except Exception as e:
        err_msg = f"서브넷 자동 선택 오류: {e}"
        print(err_msg)
        return [], err_msg


def select_route_tables_for_ha(ec2_client, vpc_id, max_az=3):
    """HA 위한 자동 라우트 테이블 선택"""
    print(
        f"VPC '{vpc_id}'에서 HA용 라우트 테이블 자동 선택 중 (최대 {max_az}개 AZ 기반)..."
    )
    selected_route_table_ids = set()
    main_route_table_id = None
    try:
        subnets_response = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        subnets_by_az = {}
        for sub in subnets_response.get("Subnets", []):
            az = sub.get("AvailabilityZone")
            if az and sub.get("State") == "available":
                if az not in subnets_by_az:
                    subnets_by_az[az] = []
                subnets_by_az[az].append(sub.get("SubnetId"))
        if not subnets_by_az:
            return [], "오류: 사용 가능 서브넷 없음"

        rt_response = ec2_client.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        subnet_to_rt_map = {}
        for rt in rt_response.get("RouteTables", []):
            rt_id = rt.get("RouteTableId")
            for assoc in rt.get("Associations", []):
                if assoc.get("Main"):
                    main_route_table_id = rt_id
                subnet_assoc_id = assoc.get("SubnetId")
                if subnet_assoc_id:
                    subnet_to_rt_map[subnet_assoc_id] = rt_id
        if not main_route_table_id and rt_response.get("RouteTables"):
            main_route_table_id = rt_response["RouteTables"][0].get(
                "RouteTableId"
            )  # 임시 fallback

        added_main_rt = False
        for az in sorted(subnets_by_az.keys()):
            if len(selected_route_table_ids) >= max_az:
                break
            found_explicit_rt_for_az = False
            for subnet_id in subnets_by_az.get(az, []):
                if subnet_id in subnet_to_rt_map:
                    selected_route_table_ids.add(subnet_to_rt_map[subnet_id])
                    found_explicit_rt_for_az = True
                    break
            if (
                not found_explicit_rt_for_az
                and main_route_table_id
                and not added_main_rt
            ):
                selected_route_table_ids.add(main_route_table_id)
                added_main_rt = True

        final_selection = list(selected_route_table_ids)
        if not final_selection and main_route_table_id:
            final_selection = [main_route_table_id]
        if not final_selection:
            return [], "오류: 라우트 테이블 자동 선택 실패"

        selected_details = [
            f"{rt}" + (" (Main)" if rt == main_route_table_id else "")
            for rt in final_selection
        ]
        info_text = f"✅ 자동으로 선택된 라우트 테이블: {', '.join(selected_details)}"
        print(info_text)
        return final_selection, info_text
    except Exception as e:
        err_msg = f"라우트 테이블 자동 선택 오류: {e}"
        print(err_msg)
        return [], err_msg


# --- 기존 엔드포인트 확인 ---
def check_existing_endpoint(ec2_client, vpc_id, service_name):
    try:
        response = ec2_client.describe_vpc_endpoints(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "service-name", "Values": [service_name]},
            ]
        )
        existing = [
            ep
            for ep in response.get("VpcEndpoints", [])
            if ep["State"] not in ["deleted", "deleting", "failed"]
        ]
        return existing
    except Exception as e:
        print(f"기존 엔드포인트 확인 오류 ({service_name}, {vpc_id}): {e}")
        return None  # 확인 불가
