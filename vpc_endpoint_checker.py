import boto3
import json
import pandas as pd
import os
import sys
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


def get_ec2_client(region):
    """지정된 리전의 EC2 클라이언트를 반환 (캐싱 사용)"""
    if region not in _ec2_clients:
        try:
            _ec2_clients[region] = boto3.client("ec2", region_name=region)
            # 간단한 테스트 호출로 자격 증명 및 리전 유효성 검사
            _ec2_clients[region].describe_regions(RegionNames=[region])
        except Exception as e:
            print(
                f"오류: 리전 '{region}'에 대한 EC2 클라이언트를 생성할 수 없습니다. {e}"
            )
            return None
    return _ec2_clients[region]


# --- CloudTrail 로그 처리 ---
def lookup_and_save_cloudtrail_events():
    """CloudTrail 이벤트를 조회하고 결과를 DataFrame으로 반환 및 CSV로 저장"""
    print("CloudTrail 이벤트 조회 중 (최근 1시간)...")
    client = boto3.client("cloudtrail")
    try:
        # 조회 기간 설정 (최근 1시간)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=10)

        paginator = client.get_paginator("lookup_events")
        response_iterator = paginator.paginate(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=1000,  # 페이지당 최대 결과 수 유지 (API 제한)
        )

        print(response_iterator)
        print(len(list(response_iterator)))

        records = []
        event_count = 0
        page_count = 0
        for page in response_iterator:
            page_count += 1
            print(f"페이지 {page_count} 처리 중...")  # 상세 로그 필요 시 주석 해제
            for event in page.get("Events", []):
                event_count += 1
                try:
                    cloudtrail_event = json.loads(event["CloudTrailEvent"])
                    event_source = cloudtrail_event.get("eventSource")

                    if event_source in TARGET_SERVICES:
                        region = cloudtrail_event.get("awsRegion")
                        if not region:  # 리전 정보가 없는 이벤트는 건너뜀
                            continue

                        records.append(
                            {
                                "eventTime": cloudtrail_event.get("eventTime"),
                                "service": TARGET_SERVICES[event_source],
                                "eventName": cloudtrail_event.get("eventName"),
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
                                "user": cloudtrail_event.get("userIdentity", {}).get(
                                    "arn", ""
                                ),
                                "region": region,
                            }
                        )
                except json.JSONDecodeError:
                    print(
                        f"경고: CloudTrailEvent JSON 파싱 실패 (EventId: {event.get('EventId')})"
                    )
                    continue
                except Exception as e:
                    print(
                        f"경고: 이벤트 처리 중 오류 발생 (EventId: {event.get('EventId')}): {e}"
                    )
                    continue

        if not records:
            print(
                "최근 1시간간 대상 서비스(S3, ECR)에 대한 CloudTrail 이벤트를 찾을 수 없습니다."
            )
            return pd.DataFrame()  # 빈 DataFrame 반환

        df = pd.DataFrame(records)
        print(f"총 {len(df)}개의 관련 이벤트 처리 완료 (최근 1시간).")

        # 1. latest_run.csv (항상 덮어쓰기)
        df.to_csv(LATEST_CSV, index=False)
        print(f"✅ 이번 실행 결과 저장 완료: {LATEST_CSV}")

        # 2. cumulative.csv (존재 시 append, 아니면 새로 생성)
        if os.path.exists(CUMULATIVE_CSV):
            df.to_csv(CUMULATIVE_CSV, mode="a", index=False, header=False)
            print(f"📎 누적 CSV에 추가 완료: {CUMULATIVE_CSV}")
        else:
            df.to_csv(CUMULATIVE_CSV, index=False)
            print(f"📌 누적 CSV 새로 생성 완료: {CUMULATIVE_CSV}")

        return df

    except Exception as e:
        print(f"CloudTrail 이벤트 조회 또는 처리 중 오류 발생: {e}")
        return pd.DataFrame()


# --- VPC 엔드포인트 분석 및 생성 ---
def analyze_endpoint_usage(filename=LATEST_CSV, threshold=ENDPOINT_MISSING_THRESHOLD):
    """CSV 파일을 분석하여 VPC 엔드포인트 미사용 횟수가 임계값을 넘는 서비스/리전 조합 반환"""
    if not os.path.exists(filename):
        print(f"분석 파일 없음: {filename}")
        return {}

    try:
        df = pd.read_csv(filename)
        missing_endpoints = df[df["usedVpcEndpoint"] == "❌ No"]

        if missing_endpoints.empty:
            print("VPC 엔드포인트 미사용 호출이 감지되지 않았습니다.")
            return {}

        # 서비스 및 리전별 미사용 호출 횟수 집계
        missing_counts = missing_endpoints.groupby(["service", "region"]).size()

        # 임계값을 넘는 경우 필터링
        potential_missing = missing_counts[missing_counts >= threshold].to_dict()

        if not potential_missing:
            print(f"VPC 엔드포인트 미사용 호출이 {threshold}회 미만입니다.")

        return potential_missing  # 예: {('S3', 'ap-northeast-2'): 10, ('ECR', 'ap-northeast-2'): 6}

    except Exception as e:
        print(f"'{filename}' 분석 중 오류 발생: {e}")
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


def prompt_for_route_tables(ec2_client, vpc_id):
    """VPC에 연결된 라우트 테이블 목록을 보여주고 선택 요청 (Gateway 엔드포인트용)"""
    try:
        route_tables = ec2_client.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["RouteTables"]
        return prompt_for_selection(
            route_tables,
            "RouteTableId",
            "RouteTableId",
            "Gateway 엔드포인트를 연결할 라우트 테이블을 선택하세요 (쉼표로 구분):",
            allow_multiple=True,
        )
    except Exception as e:
        print(f"라우트 테이블 목록 조회 중 오류: {e}")
        return []


def prompt_for_subnets(ec2_client, vpc_id):
    """VPC 내 서브넷 목록을 보여주고 선택 요청 (Interface 엔드포인트용)"""
    try:
        subnets = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["Subnets"]
        # 가용 영역(AZ) 정보도 함께 표시
        for sub in subnets:
            sub["display"] = f"{sub['SubnetId']} ({sub['AvailabilityZone']})"
        return prompt_for_selection(
            subnets,
            "display",
            "SubnetId",
            "Interface 엔드포인트를 생성할 서브넷을 선택하세요 (쉼표로 구분, HA 위해 여러 AZ 권장):",
            allow_multiple=True,
        )
    except Exception as e:
        print(f"서브넷 목록 조회 중 오류: {e}")
        return []


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
        return None  # 오류 발생 시 확인 불가로 간주


def create_vpc_endpoint_interactive(service, region, count):
    """VPC 엔드포인트 미사용 감지 시 인터랙티브하게 생성 진행"""
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

    while True:
        create_confirm = input(
            "이 서비스/리전에 대한 VPC 엔드포인트 생성을 시도하시겠습니까? (y/n): "
        ).lower()
        if create_confirm in ["y", "n"]:
            break
        else:
            print("y 또는 n만 입력해주세요.")

    if create_confirm == "n":
        print("엔드포인트 생성을 건너뜁니다.")
        return

    # 1. VPC 선택
    vpc_id = prompt_for_vpc(ec2_client)
    if not vpc_id:
        print("VPC 선택 실패. 엔드포인트 생성을 중단합니다.")
        return

    # 서비스 이름 결정 (리전 포함)
    # 참고: https://docs.aws.amazon.com/vpc/latest/privatelink/aws-services-privatelink-support.html
    endpoint_type = None
    service_name_to_create = None
    if service == "S3":
        endpoint_type = "Gateway"
        service_name_to_create = f"com.amazonaws.{region}.s3"
    elif service == "ECR":
        endpoint_type = "Interface"
        # CloudTrail 로그에는 보통 ecr.amazonaws.com 이 찍히지만,
        # 실제 Docker push/pull은 ecr.dkr 엔드포인트, API 호출은 ecr.api 엔드포인트 사용
        # 여기서는 dkr 엔드포인트 생성을 제안 (가장 흔한 트래픽 유발 원인)
        service_name_to_create = f"com.amazonaws.{region}.ecr.dkr"
        print("ℹ️ 참고: ECR Docker 트래픽용 'ecr.dkr' 엔드포인트를 생성합니다.")
        print(
            "      ECR API 호출(예: describe-repositories)도 VPC 내부에서 하려면 'ecr.api' 엔드포인트도 별도로 필요할 수 있습니다."
        )
    else:
        print(f"오류: 지원되지 않는 서비스 '{service}'입니다.")
        return

    # 2. 기존 엔드포인트 확인
    existing_endpoints = check_existing_endpoint(
        ec2_client, vpc_id, service_name_to_create
    )
    if existing_endpoints is None:  # 확인 중 오류
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

    # 3. 필요 정보 수집 및 생성
    try:
        print(
            f"\nVPC '{vpc_id}'에 '{service_name_to_create}' ({endpoint_type} 타입) 엔드포인트 생성을 시작합니다."
        )
        creation_params = {
            "VpcEndpointType": endpoint_type,
            "VpcId": vpc_id,
            "ServiceName": service_name_to_create,
            # TagSpecifications를 사용하여 이름 태그 추가 가능
            "TagSpecifications": [
                {
                    "ResourceType": "vpc-endpoint",
                    "Tags": [{"Key": "Name", "Value": f"{vpc_id}-{service}-endpoint"}],
                }
            ],
        }

        if endpoint_type == "Gateway":
            route_table_ids = prompt_for_route_tables(ec2_client, vpc_id)
            if not route_table_ids:
                print("라우트 테이블 선택 실패. 엔드포인트 생성을 중단합니다.")
                return
            creation_params["RouteTableIds"] = route_table_ids
        elif endpoint_type == "Interface":
            subnet_ids = prompt_for_subnets(ec2_client, vpc_id)
            if not subnet_ids:
                print("서브넷 선택 실패. 엔드포인트 생성을 중단합니다.")
                return
            security_group_ids = prompt_for_security_groups(ec2_client, vpc_id)
            if not security_group_ids:
                print("보안 그룹 선택 실패. 엔드포인트 생성을 중단합니다.")
                return
            creation_params["SubnetIds"] = subnet_ids
            creation_params["SecurityGroupIds"] = security_group_ids
            creation_params["PrivateDnsEnabled"] = True  # Private DNS 활성화 권장

        print("\n생성 파라미터:")
        print(json.dumps(creation_params, indent=2))

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
        print(f"\n❌ VPC 엔드포인트 생성 중 오류 발생: {e}")


# --- 메인 실행 로직 ---
def main():
    # 1. CloudTrail 로그 조회 및 저장
    lookup_and_save_cloudtrail_events()

    # 2. 최신 로그 분석
    print("\n--- VPC 엔드포인트 사용 현황 분석 ---")
    potential_missing = analyze_endpoint_usage()

    if not potential_missing:
        print("VPC 엔드포인트 생성이 필요한 서비스/리전 조합이 감지되지 않았습니다.")
        return

    # 3. 감지된 경우 인터랙티브 생성 시도
    print("\n--- VPC 엔드포인트 생성 제안 ---")
    for (service, region), count in potential_missing.items():
        create_vpc_endpoint_interactive(service, region, count)
        print("-" * 40)

    print("\n모든 분석 및 제안 프로세스가 완료되었습니다.")


if __name__ == "__main__":
    main()
