import boto3
import json
import pandas as pd
import os
import sys
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone

# --- 설정 ---
# 추적할 AWS 서비스 (eventSource: 서비스 식별자)
TARGET_SERVICES = {
    "s3.amazonaws.com": "S3",
    "ecr.amazonaws.com": "ECR",
    # 필요시 다른 서비스 추가
}
# VPC 엔드포인트 미사용 임계값
ENDPOINT_MISSING_THRESHOLD = 5
# CSV 파일 경로
LATEST_CSV = "latest_run.csv"
CUMULATIVE_CSV = "cumulative.csv"
# --- 설정 끝 ---

# --- Boto3 클라이언트 관리 ---
_ec2_clients = {}
_cloudtrail_clients = {}  # CloudTrail 클라이언트 캐싱 추가


def get_ec2_client(region):
    """지정된 리전의 EC2 클라이언트를 반환 (캐싱 사용)"""
    if region not in _ec2_clients:
        try:
            _ec2_clients[region] = boto3.client("ec2", region_name=region)
            _ec2_clients[region].describe_regions(RegionNames=[region])
        except Exception as e:
            print(
                f"오류: 리전 '{region}'에 대한 EC2 클라이언트를 생성할 수 없습니다. {e}"
            )
            return None
    return _ec2_clients[region]


def get_cloudtrail_client(region):
    """지정된 리전의 CloudTrail 클라이언트를 반환 (캐싱 사용)"""
    if region not in _cloudtrail_clients:
        try:
            _cloudtrail_clients[region] = boto3.client("cloudtrail", region_name=region)
        except Exception as e:
            print(
                f"오류: 리전 '{region}'에 대한 CloudTrail 클라이언트를 생성할 수 없습니다. {e}"
            )
            return None
    return _cloudtrail_clients[region]


# --- EC2 인스턴스 정보 조회 ---
def get_instance_network_details(region, instance_id):
    """주어진 인스턴스 ID로부터 VPC, 서브넷, 보안 그룹 정보를 조회"""
    print(f"인스턴스 '{instance_id}'의 네트워크 정보 조회 중 (리전: {region})...")
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
        subnet_id = instance.get("SubnetId")
        security_groups = instance.get("SecurityGroups", [])
        security_group_ids = [
            sg.get("GroupId") for sg in security_groups if sg.get("GroupId")
        ]
        if not vpc_id or not subnet_id or not security_group_ids:
            print(
                f"오류: 인스턴스 '{instance_id}'에서 필수 네트워크 정보(VPC, 서브넷, 보안그룹)를 가져올 수 없습니다."
            )
            return None
        return {
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "security_group_ids": security_group_ids,
        }
    except ec2_client.exceptions.ClientError as e:
        if "InvalidInstanceID.NotFound" in str(e):
            print(f"오류: 인스턴스 ID '{instance_id}'를 찾을 수 없습니다.")
        else:
            print(f"인스턴스 정보 조회 중 오류 발생 ({instance_id}): {e}")
        return None
    except Exception as e:
        print(f"인스턴스 정보 조회 중 예기치 않은 오류 발생 ({instance_id}): {e}")
        return None


# --- CloudTrail 로그 처리 ---
def lookup_service_events_and_filter_by_instance(
    region, target_instance_id=None, days=1
):
    """CloudTrail 이벤트를 조회하고 (선택적으로) 특정 인스턴스 ID 기준으로 필터링하여 DataFrame 반환"""
    mode = f"인스턴스 ID({target_instance_id})" if target_instance_id else "일반"
    print(f"CloudTrail 이벤트 조회 중 ({mode}, 최근 {days}일)... 리전: {region}")

    client = get_cloudtrail_client(region)
    if not client:
        return pd.DataFrame()

    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        paginator = client.get_paginator("lookup_events")
        response_iterator = paginator.paginate(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=1000,
        )

        records = []
        event_count = 0
        page_count = 0
        for page in response_iterator:
            page_count += 1
            for event in page.get("Events", []):
                event_count += 1
                try:
                    cloudtrail_event = json.loads(event["CloudTrailEvent"])
                    event_source = cloudtrail_event.get("eventSource")

                    # 1. TARGET_SERVICES 에 포함되는지 확인
                    if event_source in TARGET_SERVICES:
                        user_identity = cloudtrail_event.get("userIdentity", {})
                        principal_id = user_identity.get("principalId", "")

                        # 2. 인스턴스 ID 필터링 (target_instance_id 가 제공된 경우)
                        # userIdentity.principalId 에 :instance_id 형태가 포함되는지 확인
                        if (
                            target_instance_id
                            and f":{target_instance_id}" not in principal_id
                        ):
                            continue  # 인스턴스 ID 불일치 시 건너뜀

                        event_region = cloudtrail_event.get("awsRegion")
                        if not event_region:
                            continue

                        # 레코드 추가
                        records.append(
                            {
                                "eventTime": cloudtrail_event.get("eventTime"),
                                "service": TARGET_SERVICES[event_source],
                                "eventName": cloudtrail_event.get("eventName"),
                                # sourceIPAddress 는 인스턴스 IP가 아닐 수 있으므로 참고용으로만 유지
                                "sourceIPAddress": cloudtrail_event.get(
                                    "sourceIPAddress"
                                ),
                                "vpcEndpointId": cloudtrail_event.get(
                                    "vpcEndpointId", None
                                ),
                                "usedVpcEndpoint": (
                                    "✅ Yes"
                                    if cloudtrail_event.get("vpcEndpointId")
                                    else "❌ No"
                                ),
                                # 사용자 정보는 userIdentity 에서 가져오는 것이 더 정확할 수 있음
                                "user": user_identity.get(
                                    "arn", user_identity.get("userName", "N/A")
                                ),  # ARN 또는 userName 사용
                                "region": event_region,
                                # 디버깅/참고용 필드 추가 (선택적)
                                # "principalId": principal_id,
                                # "userIdentityType": user_identity.get("type")
                            }
                        )
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(
                        f"경고: 이벤트 처리 중 오류 발생 (EventId: {event.get('EventId')}): {e}"
                    )
                    continue

        if not records:
            print(
                f"대상 서비스({', '.join(TARGET_SERVICES.values())}) 관련 CloudTrail 이벤트를 찾을 수 없습니다 ({mode})."
            )
            return pd.DataFrame()

        df = pd.DataFrame(records)
        print(f"총 {len(df)}개의 관련 이벤트 처리 완료 ({mode}, 최근 {days}일).")

        # 인스턴스 ID 필터링 모드가 아닐 때만 CSV 저장
        if not target_instance_id:
            df.to_csv(LATEST_CSV, index=False)
            print(f"✅ 이번 실행 결과 저장 완료: {LATEST_CSV}")
            if os.path.exists(CUMULATIVE_CSV):
                df.to_csv(CUMULATIVE_CSV, mode="a", index=False, header=False)
                print(f"📎 누적 CSV에 추가 완료: {CUMULATIVE_CSV}")
            else:
                df.to_csv(CUMULATIVE_CSV, index=False)
                print(f"📌 누적 CSV 새로 생성 완료: {CUMULATIVE_CSV}")

        return df

    except client.exceptions.InvalidTimeRangeException:
        print(f"오류: CloudTrail 조회 기간(최대 90일)이 잘못되었습니다. ({days}일)")
        return pd.DataFrame()
    except Exception as e:
        print(f"CloudTrail 이벤트 조회 또는 처리 중 오류 발생: {e}")
        return pd.DataFrame()


# --- VPC 엔드포인트 분석 및 생성 ---
def analyze_endpoint_usage(events_df, threshold=ENDPOINT_MISSING_THRESHOLD):
    """이벤트 DataFrame을 분석하여 VPC 엔드포인트 미사용 횟수가 임계값을 넘는 서비스/리전 조합 반환"""
    if events_df.empty:
        return {}
    try:
        missing_endpoints = events_df[events_df["usedVpcEndpoint"] == "❌ No"]
        if missing_endpoints.empty:
            print("분석된 이벤트 중 VPC 엔드포인트 미사용 호출이 감지되지 않았습니다.")
            return {}
        missing_counts = missing_endpoints.groupby(["service", "region"]).size()
        potential_missing = missing_counts[missing_counts >= threshold].to_dict()
        if not potential_missing:
            print(f"VPC 엔드포인트 미사용 호출이 {threshold}회 미만입니다.")
        return potential_missing
    except Exception as e:
        print(f"이벤트 데이터 분석 중 오류 발생: {e}")
        return {}


def prompt_for_selection(
    items, display_key, id_key, prompt_message, allow_multiple=False, min_selection=1
):
    """사용자에게 목록을 보여주고 항목을 선택하도록 요청"""
    if not items:
        print("선택할 항목이 없습니다.")
        return None if not allow_multiple else []

    print(f"\n{prompt_message}")
    for i, item in enumerate(items):
        display_text = item.get(display_key, "N/A")
        item_id = item.get(id_key, "N/A")
        # 이름 태그가 있으면 함께 표시
        name_tag = next(
            (tag["Value"] for tag in item.get("Tags", []) if tag["Key"] == "Name"), None
        )
        if name_tag:
            print(f"  {i+1}. {display_text} (ID: {item_id}, Name: {name_tag})")
        else:
            print(f"  {i+1}. {display_text} (ID: {item_id})")

    selected_indices = []
    while True:
        try:
            if allow_multiple:
                prompt = f"번호를 쉼표로 구분하여 입력하세요 (최소 {min_selection}개): "
            else:
                prompt = "번호를 입력하세요: "
            choice = input(prompt).strip()

            if not choice:
                print("입력이 없습니다. 다시 시도하세요.")
                continue

            indices = [int(x.strip()) - 1 for x in choice.split(",")]

            if any(idx < 0 or idx >= len(items) for idx in indices):
                print("잘못된 번호가 포함되어 있습니다. 다시 시도하세요.")
                continue

            if not allow_multiple and len(indices) > 1:
                print("하나의 번호만 입력하세요.")
                continue

            if allow_multiple and len(indices) < min_selection:
                print(f"최소 {min_selection}개 이상 선택해야 합니다.")
                continue

            selected_indices = indices
            break
        except ValueError:
            print("숫자 또는 쉼표로 구분된 숫자만 입력하세요.")
        except Exception as e:
            print(f"입력 처리 중 오류 발생: {e}")
            return None if not allow_multiple else []

    if allow_multiple:
        return [items[i][id_key] for i in selected_indices]
    else:
        return items[selected_indices[0]][id_key]


def prompt_for_vpc(ec2_client):
    """사용 가능한 VPC 목록을 보여주고 선택 요청"""
    try:
        vpcs = ec2_client.describe_vpcs()["Vpcs"]
        return prompt_for_selection(
            vpcs, "VpcId", "VpcId", "VPC 엔드포인트를 생성할 VPC를 선택하세요:"
        )
    except Exception as e:
        print(f"VPC 목록 조회 중 오류: {e}")
        return None


def prompt_for_security_groups(ec2_client, vpc_id):
    """VPC 내 보안 그룹 목록을 보여주고 선택 요청 (Interface 엔드포인트용)"""
    try:
        sgs = ec2_client.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
        for sg in sgs:
            sg["display"] = f"{sg['GroupId']} ({sg['GroupName']})"
        return prompt_for_selection(
            sgs,
            "display",
            "GroupId",
            "Interface 엔드포인트에 연결할 보안 그룹을 선택하세요 (쉼표로 구분):",
            allow_multiple=True,
        )
    except Exception as e:
        print(f"보안 그룹 목록 조회 중 오류: {e}")
        return []


def check_existing_endpoint(ec2_client, vpc_id, service_name):
    """주어진 VPC에 특정 서비스 엔드포인트가 이미 존재하는지 확인"""
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
        print(f"기존 VPC 엔드포인트 확인 중 오류 ({service_name}, {vpc_id}): {e}")
        return None


# 새로운 함수: 고가용성을 위한 자동 서브넷 선택
def select_subnets_for_ha(ec2_client, vpc_id, max_az=3):
    """주어진 VPC에서 고가용성을 위해 여러 다른 AZ의 서브넷을 자동으로 선택 (최대 max_az개)"""
    print(
        f"\nVPC '{vpc_id}' 내에서 고가용성을 위한 서브넷 자동 선택 중 (최대 {max_az}개 AZ)..."
    )
    try:
        subnets = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["Subnets"]

        if not subnets:
            print(f"오류: VPC '{vpc_id}' 내에서 서브넷을 찾을 수 없습니다.")
            return []

        subnets_by_az = {}
        for sub in subnets:
            az = sub.get("AvailabilityZone")
            subnet_id = sub.get("SubnetId")
            # 서브넷 상태 확인 (선택적: available 상태만 고려)
            if az and subnet_id and sub.get("State") == "available":
                if az not in subnets_by_az:
                    subnets_by_az[az] = []
                subnets_by_az[az].append(subnet_id)

        if not subnets_by_az:
            print(
                f"오류: VPC '{vpc_id}' 내에서 사용 가능한 상태의 서브넷을 찾을 수 없습니다."
            )
            return []

        selected_subnet_ids = []
        selected_azs_info = []
        # AZ 이름 순으로 정렬하여 일관성 유지
        sorted_azs = sorted(subnets_by_az.keys())

        for az in sorted_azs:
            if len(selected_subnet_ids) >= max_az:
                break
            # 해당 AZ에서 첫 번째 서브넷 선택
            if subnets_by_az[az]:
                selected_subnet = subnets_by_az[az][0]
                selected_subnet_ids.append(selected_subnet)
                selected_azs_info.append(f"{selected_subnet} ({az})")

        if not selected_subnet_ids:
            print(f"오류: VPC '{vpc_id}' 내에서 자동 선택할 서브넷을 찾지 못했습니다.")
            return []

        print(f"✅ 자동으로 선택된 서브넷: {', '.join(selected_azs_info)}")
        return selected_subnet_ids

    except Exception as e:
        print(f"서브넷 자동 선택 중 오류 발생 (VPC: {vpc_id}): {e}")
        return []


# 새로운 함수: 고가용성을 위한 자동 라우트 테이블 선택
def select_route_tables_for_ha(ec2_client, vpc_id, max_az=3):
    """주어진 VPC에서 다른 AZ의 서브넷과 연결된 라우트 테이블을 자동으로 선택 (최대 max_az개)"""
    print(
        f"\nVPC '{vpc_id}' 내에서 고가용성을 위한 라우트 테이블 자동 선택 중 (최대 {max_az}개 AZ 기반)..."
    )
    selected_route_table_ids = set()
    main_route_table_id = None

    try:
        # 1. VPC 내 서브넷 조회 및 AZ별 그룹화
        subnets_response = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        subnets_by_az = {}
        all_vpc_subnet_ids = set()
        for sub in subnets_response.get("Subnets", []):
            az = sub.get("AvailabilityZone")
            subnet_id = sub.get("SubnetId")
            if az and subnet_id and sub.get("State") == "available":
                all_vpc_subnet_ids.add(subnet_id)
                if az not in subnets_by_az:
                    subnets_by_az[az] = []
                subnets_by_az[az].append(subnet_id)

        if not subnets_by_az:
            print(
                f"오류: VPC '{vpc_id}' 내에서 사용 가능한 서브넷을 찾을 수 없어 라우트 테이블을 선택할 수 없습니다."
            )
            return []

        # 2. VPC 내 라우트 테이블 조회 및 서브넷 연결 정보 매핑
        rt_response = ec2_client.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        subnet_to_rt_map = {}
        for rt in rt_response.get("RouteTables", []):
            rt_id = rt.get("RouteTableId")
            is_main = False
            for assoc in rt.get("Associations", []):
                if assoc.get("Main"):  # 주 라우트 테이블 확인
                    is_main = True
                    main_route_table_id = rt_id
                subnet_assoc_id = assoc.get("SubnetId")
                if subnet_assoc_id:
                    subnet_to_rt_map[subnet_assoc_id] = rt_id  # 명시적 연결 매핑

        if not main_route_table_id:
            # 이론적으로는 항상 주 라우트 테이블이 있어야 함
            print(f"경고: VPC '{vpc_id}'의 주 라우트 테이블을 찾을 수 없습니다.")
            # 첫번째 라우트 테이블을 임시로 사용하거나 오류 처리 필요
            if rt_response.get("RouteTables"):
                main_route_table_id = rt_response["RouteTables"][0].get("RouteTableId")
                print(
                    f" -> 임시로 라우트 테이블 '{main_route_table_id}'을 주 테이블로 간주합니다."
                )
            else:
                print(f"오류: VPC '{vpc_id}'에 라우트 테이블이 없습니다.")
                return []

        # 3. AZ별로 순회하며 라우트 테이블 선택
        sorted_azs = sorted(subnets_by_az.keys())
        added_main_rt = False  # 주 라우트 테이블 추가 여부 플래그

        for az in sorted_azs:
            if len(selected_route_table_ids) >= max_az:
                break

            found_explicit_rt_for_az = False
            subnets_in_this_az = subnets_by_az.get(az, [])

            for subnet_id in subnets_in_this_az:
                if subnet_id in subnet_to_rt_map:
                    rt_id_to_add = subnet_to_rt_map[subnet_id]
                    selected_route_table_ids.add(rt_id_to_add)
                    found_explicit_rt_for_az = True
                    # print(f"  -> AZ '{az}'의 서브넷({subnet_id})과 연결된 라우트 테이블 '{rt_id_to_add}' 선택")
                    break  # 해당 AZ에 대해 하나만 추가

            # 해당 AZ의 서브넷에 명시적으로 연결된 라우트 테이블이 없다면 주 라우트 테이블 추가 (아직 추가 안됐으면)
            if (
                not found_explicit_rt_for_az
                and main_route_table_id
                and not added_main_rt
            ):
                selected_route_table_ids.add(main_route_table_id)
                added_main_rt = True
                # print(f"  -> AZ '{az}'에 명시적 연결 테이블 없어 주 라우트 테이블 '{main_route_table_id}' 추가")

        # 4. 최종 결과 확인 및 반환
        final_selection = list(selected_route_table_ids)
        if not final_selection:
            # 모든 AZ에서 실패하고 주 테이블도 없거나 추가 못 한 경우 (이론상 드묾)
            print(
                f"오류: VPC '{vpc_id}' 내에서 자동 선택할 라우트 테이블을 찾지 못했습니다. 주 라우트 테이블: {main_route_table_id}"
            )
            if main_route_table_id:
                print(f" -> 주 라우트 테이블 '{main_route_table_id}'만 선택합니다.")
                final_selection = [main_route_table_id]
            else:
                return []

        # 선택 결과 출력 (선택적 상세화)
        selected_details = []
        for rt_id in final_selection:
            detail = f"{rt_id}" + (" (Main)" if rt_id == main_route_table_id else "")
            selected_details.append(detail)

        print(f"✅ 자동으로 선택된 라우트 테이블: {', '.join(selected_details)}")
        return final_selection

    except Exception as e:
        print(f"라우트 테이블 자동 선택 중 오류 발생 (VPC: {vpc_id}): {e}")
        return []


def create_vpc_endpoint_interactive(service, region, count, reference_instance_id=None):
    """VPC 엔드포인트 미사용 감지 시 인터랙티브하게 또는 자동으로 생성 진행"""
    print("-" * 40)
    print(
        f"🚨 감지: 서비스 '{service}', 리전 '{region}'에서 VPC 엔드포인트 미사용 호출 {count}회 발견 (임계값: {ENDPOINT_MISSING_THRESHOLD}회)"
    )
    ec2_client = get_ec2_client(region)
    if not ec2_client:
        print(
            f"오류: 리전 '{region}'에 접근할 수 없어 엔드포인트 생성을 진행할 수 없습니다."
        )
        return
    vpc_id = None
    route_table_ids = None
    subnet_ids = None  # 자동 선택될 예정
    security_group_ids = None  # 기존 로직 유지
    auto_filled_vpc = False
    auto_filled_sg = False

    # 1. VPC ID 결정 (참조 인스턴스 또는 수동)
    if reference_instance_id:
        instance_details = get_instance_network_details(region, reference_instance_id)
        if instance_details:
            vpc_id = instance_details["vpc_id"]
            print(
                f"\nℹ️ 참조 인스턴스 '{reference_instance_id}'의 VPC ({vpc_id}) 정보를 사용합니다."
            )
            auto_filled_vpc = True
            # 보안 그룹도 참조 인스턴스 것 사용
            security_group_ids = instance_details["security_group_ids"]
            print(f"  -> 참조 인스턴스의 보안 그룹 ID: {', '.join(security_group_ids)}")
            auto_filled_sg = True
        else:
            print(
                f"오류: 참조 인스턴스 '{reference_instance_id}'의 정보를 가져올 수 없어 수동으로 진행합니다."
            )

    if not vpc_id:
        vpc_id = prompt_for_vpc(ec2_client)
        if not vpc_id:
            print("VPC 선택 실패. 엔드포인트 생성을 중단합니다.")
            return

    # 2. 서비스 타입 결정 및 기존 엔드포인트 확인
    endpoint_type = None
    service_name_to_create = None
    if service == "S3":
        endpoint_type = "Gateway"
        service_name_to_create = f"com.amazonaws.{region}.s3"
    elif service == "ECR":
        endpoint_type = "Interface"
        service_name_to_create = f"com.amazonaws.{region}.ecr.dkr"
        print("ℹ️ 참고: ECR Docker 트래픽용 'ecr.dkr' 엔드포인트를 생성합니다.")
        print(
            "      ECR API 호출(예: describe-repositories)도 VPC 내부에서 하려면 'ecr.api' 엔드포인트도 별도로 필요할 수 있습니다."
        )
    else:
        print(f"오류: 지원되지 않는 서비스 '{service}'입니다.")
        return
    existing_endpoints = check_existing_endpoint(
        ec2_client, vpc_id, service_name_to_create
    )
    if existing_endpoints is None:
        print("기존 엔드포인트 확인 실패. 생성을 중단합니다.")
        return
    if existing_endpoints:
        print(
            f"이미 VPC '{vpc_id}'에 '{service_name_to_create}' 엔드포인트가 존재합니다:"
        )
        for ep in existing_endpoints:
            print(f"  - ID: {ep['VpcEndpointId']}, 상태: {ep['State']}")
        print("엔드포인트 생성을 건너뜁니다.")
        return

    # 3. 생성 파라미터 구성 (타입별 처리)
    try:
        print(
            f"\nVPC '{vpc_id}'에 '{service_name_to_create}' ({endpoint_type} 타입) 엔드포인트 생성을 준비합니다."
        )
        creation_params = {
            "VpcEndpointType": endpoint_type,
            "VpcId": vpc_id,
            "ServiceName": service_name_to_create,
            "TagSpecifications": [
                {
                    "ResourceType": "vpc-endpoint",
                    "Tags": [
                        {"Key": "Name", "Value": f"{vpc_id}-{service}-endpoint"},
                        {
                            "Key": "CreatedFromReferenceInstance",
                            "Value": (
                                reference_instance_id
                                if reference_instance_id
                                else "Manual"
                            ),
                        },
                    ],
                }
            ],
        }

        if endpoint_type == "Gateway":
            # Gateway: 라우트 테이블 자동 선택
            route_table_ids = select_route_tables_for_ha(ec2_client, vpc_id)
            if not route_table_ids:
                print("라우트 테이블 자동 선택 실패. 엔드포인트 생성을 중단합니다.")
                return
            creation_params["RouteTableIds"] = route_table_ids

        elif endpoint_type == "Interface":
            # Interface: 서브넷 자동 선택, 보안 그룹은 자동(참조) 또는 수동
            subnet_ids = select_subnets_for_ha(ec2_client, vpc_id)
            if not subnet_ids:
                print("서브넷 자동 선택 실패. 엔드포인트 생성을 중단합니다.")
                return
            creation_params["SubnetIds"] = subnet_ids

            if not auto_filled_sg:  # 참조 인스턴스에서 보안그룹 가져오지 못한 경우
                security_group_ids = prompt_for_security_groups(ec2_client, vpc_id)
                if not security_group_ids:
                    print("보안 그룹 선택 실패. 엔드포인트 생성을 중단합니다.")
                    return
            creation_params["SecurityGroupIds"] = security_group_ids
            creation_params["PrivateDnsEnabled"] = True

        # 4. 최종 확인 및 생성 요청
        print("\n생성 파라미터:")
        print(json.dumps(creation_params, indent=2, default=str))
        confirm_create = input(
            "위 정보로 VPC 엔드포인트를 생성하시겠습니까? (y/n): "
        ).lower()
        if confirm_create == "y":
            response = ec2_client.create_vpc_endpoint(**creation_params)
            endpoint_id = response.get("VpcEndpoint", {}).get("VpcEndpointId", "N/A")
            print(f"\n✅ VPC 엔드포인트 생성 요청 성공!")
            print(f"   엔드포인트 ID: {endpoint_id}")
            print(
                f"   상태: {response.get('VpcEndpoint', {}).get('State', 'N/A')} (pending 상태일 수 있습니다)"
            )
        else:
            print("엔드포인트 생성이 취소되었습니다.")

    except Exception as e:
        # 오류 메시지를 안전하게 처리하여 출력
        error_message = ""
        try:
            # 먼저 일반적인 문자열 변환 시도
            error_message = str(e)
        except UnicodeDecodeError:
            # UnicodeDecodeError 발생 시, repr() 사용 또는 바이트를 직접 처리 시도
            try:
                # repr()은 종종 문제를 우회함
                error_message = repr(e)
            except Exception:
                # repr() 마저 실패하면 간단한 메시지 출력
                error_message = "오류 메시지를 디코딩할 수 없습니다."
        except Exception as format_e:
            # 그 외 오류 메시지 포맷팅 오류
            error_message = f"오류 메시지 처리 중 다른 오류 발생: {format_e}"

        print(f"\n❌ VPC 엔드포인트 생성 중 오류 발생: {error_message}")
        # 디버깅을 위해 트레이스백 출력 (선택 사항)
        # import traceback
        # traceback.print_exc()


# --- 메인 실행 로직 ---
def main():
    parser = argparse.ArgumentParser(
        description="AWS VPC 엔드포인트 사용 현황 분석 및 자동 생성 도구"
    )
    parser.add_argument(
        "--instance-id",
        metavar="INSTANCE_ID",
        help="[자동 분석/생성 모드] 트래픽을 분석하고 엔드포인트 생성 시 참조할 EC2 인스턴스 ID. 지정 시 아래 --region 필수.",
    )
    parser.add_argument(
        "--region",
        metavar="AWS_REGION",
        required=False,  # instance-id 사용 시 필수로 만들 예정
        help="[자동 분석/생성 모드] --instance-id 와 함께 사용하여 분석 및 생성 대상 리전을 지정합니다.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=1,
        metavar="N",
        help="CloudTrail 이벤트 조회 기간(일)을 지정합니다. (기본값: 1)",
    )
    parser.add_argument(
        "--reference-instance-id",
        metavar="REF_INSTANCE_ID",
        help="[수동 생성 시 옵션] 일반 분석 후 엔드포인트 생성 시 참조할 인스턴스 ID (네트워크 자동 구성용). --instance-id 와 동시 사용 불가.",
    )
    args = parser.parse_args()

    # --- 모드 분기 --- #
    if args.instance_id:
        if not args.region:
            parser.error("--instance-id 옵션을 사용하려면 --region 옵션이 필수입니다.")
        if args.reference_instance_id:
            parser.error(
                "--instance-id 와 --reference-instance-id 는 함께 사용할 수 없습니다."
            )
        print(
            f"--- 자동 분석/생성 모드 시작 (인스턴스: {args.instance_id}, 리전: {args.region}) ---"
        )
        instance_events_df = lookup_service_events_and_filter_by_instance(
            args.region, target_instance_id=args.instance_id, days=args.days
        )
        if instance_events_df.empty:
            print(
                f"인스턴스 '{args.instance_id}'에서 발생한 대상 서비스 트래픽을 찾을 수 없어 분석을 종료합니다."
            )
            sys.exit(0)
        print(
            f"\n--- 인스턴스 '{args.instance_id}' 트래픽 기반 VPC 엔드포인트 사용 현황 분석 ---"
        )
        potential_missing = analyze_endpoint_usage(instance_events_df)
        if not potential_missing:
            print(
                "분석 결과, 이 인스턴스 트래픽에 대해 VPC 엔드포인트 생성이 필요한 경우가 감지되지 않았습니다."
            )
            sys.exit(0)
        print(
            f"\n--- VPC 엔드포인트 생성 제안 (인스턴스 '{args.instance_id}' 기반 자동 구성) ---"
        )
        for (service, region), count in potential_missing.items():
            create_vpc_endpoint_interactive(
                service, region, count, reference_instance_id=args.instance_id
            )
            print("-" * 40)
        print("\n자동 분석 및 제안 프로세스가 완료되었습니다.")
    else:
        ref_id_for_creation = None
        if args.reference_instance_id:
            print(
                f"--- 일반 분석 및 엔드포인트 생성 모드 시작 (참조 인스턴스 ID: {args.reference_instance_id}) ---"
            )
            ref_region = input(
                f"참조 인스턴스 '{args.reference_instance_id}'가 있는 리전을 입력하세요: "
            ).strip()
            if not ref_region:
                print("리전 입력이 없어 진행할 수 없습니다.")
                sys.exit(1)
            if not get_instance_network_details(ref_region, args.reference_instance_id):
                print(
                    f"오류: 참조 인스턴스 '{args.reference_instance_id}' 정보를 '{ref_region}' 리전에서 찾을 수 없습니다."
                )
                sys.exit(1)
            print(
                f"참조 인스턴스 확인 완료. 일반 분석 후 생성 시 해당 인스턴스 정보를 사용합니다."
            )
            ref_id_for_creation = args.reference_instance_id
        else:
            print("--- 일반 분석 및 엔드포인트 생성 모드 시작 (수동 구성) ---")
        default_region = boto3.Session().region_name
        if not default_region:
            print(
                "오류: AWS 리전을 결정할 수 없습니다. AWS 설정을 확인하거나 명시적으로 지정해주세요."
            )
            sys.exit(1)
        print(f"기본 리전 '{default_region}'에서 일반 트래픽 분석을 시작합니다.")
        general_events_df = lookup_service_events_and_filter_by_instance(
            default_region, days=args.days
        )
        if general_events_df.empty:
            print(
                f"리전 '{default_region}'에서 처리할 CloudTrail 이벤트가 없어 분석을 종료합니다."
            )
            sys.exit(0)
        print(
            f"\n--- 리전 '{default_region}' 전체 트래픽 기반 VPC 엔드포인트 사용 현황 분석 ---"
        )
        potential_missing = analyze_endpoint_usage(general_events_df)
        if not potential_missing:
            print("분석 결과, VPC 엔드포인트 생성이 필요한 경우가 감지되지 않았습니다.")
            sys.exit(0)
        print("\n--- VPC 엔드포인트 생성 제안 ---")
        for (service, region), count in potential_missing.items():
            create_vpc_endpoint_interactive(
                service, region, count, reference_instance_id=ref_id_for_creation
            )
            print("-" * 40)
        print("\n일반 분석 및 제안 프로세스가 완료되었습니다.")


if __name__ == "__main__":
    main()
