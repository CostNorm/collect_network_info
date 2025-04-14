import boto3
import json
import base64
import requests
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs
import traceback

# 생성된 유틸리티 파일 임포트
from vpc_endpoint_utils import (
    TARGET_SERVICES,
    ENDPOINT_MISSING_THRESHOLD,
    get_ec2_client,
    get_cloudtrail_client,
    get_instance_network_details,
    lookup_service_events_and_filter_by_instance,
    analyze_endpoint_usage,
    select_subnets_for_ha,
    select_route_tables_for_ha,
    check_existing_endpoint,
)

# --- Lambda 환경 설정 ---
TARGET_SERVICES = {
    "s3.amazonaws.com": "S3",
    "ecr.amazonaws.com": "ECR",
}
SELF_FUNCTION_NAME = "check_vpc_endpoint_presence"
lambda_client = boto3.client("lambda")

# Boto3 CloudTrail 클라이언트 캐싱 (선택적이지만 권장)
_cloudtrail_clients = {}


def get_cloudtrail_client(region):
    # 지정된 리전의 CloudTrail 클라이언트를 반환 (캐싱 사용)
    if region not in _cloudtrail_clients:
        try:
            _cloudtrail_clients[region] = boto3.client("cloudtrail", region_name=region)
        except Exception as e:
            print(
                f"오류: 리전 '{region}'에 대한 CloudTrail 클라이언트를 생성할 수 없습니다. {e}"
            )
            return None
    return _cloudtrail_clients[region]


# --- CloudTrail 로그 처리 (Instance ID 기반 필터링) ---
def lookup_instance_events(region, instance_id, days=None, hours=None, max_results=20):
    """특정 인스턴스 ID와 관련된 CloudTrail 이벤트를 조회하고 결과를 문자열로 반환"""
    # 시간/일 단위 결정
    time_unit = "일"
    time_value = 1  # 기본값 1일
    if hours is not None:
        time_unit = "시간"
        time_value = hours
        lookup_days = None  # 시간 우선
    elif days is not None:
        time_unit = "일"
        time_value = days
        lookup_days = days
    else:  # 둘 다 None이면 기본값 사용
        lookup_days = 1

    print(
        f"CloudTrail 이벤트 조회 중 (인스턴스 ID: {instance_id}, 최근 {time_value}{time_unit})... 리전: {region}"
    )
    client = get_cloudtrail_client(region)
    if not client:
        return f"오류: 리전 '{region}'의 CloudTrail 클라이언트를 가져올 수 없습니다."

    records = []
    page_count = 0
    event_count = 0
    try:
        end_time = datetime.now(timezone.utc)
        # 시작 시간 계산
        if hours is not None:
            start_time = end_time - timedelta(hours=hours)
        else:
            start_time = end_time - timedelta(days=lookup_days)

        paginator = client.get_paginator("lookup_events")
        response_iterator = paginator.paginate(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=1000,
        )

        for page in response_iterator:
            page_count += 1
            # print(f"페이지 {page_count} 처리 중...") # 상세 로그 필요 시 주석 해제
            for event in page.get("Events", []):
                event_count += 1
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

                        # VPC 엔드포인트 사용 여부 확인
                        vpc_endpoint_id = cloudtrail_event.get("vpcEndpointId", None)
                        used_endpoint = "Yes" if vpc_endpoint_id else "No"

                        records.append(
                            {
                                "EventTime": cloudtrail_event.get("eventTime"),
                                "EventName": cloudtrail_event.get("eventName"),
                                "User": user_identity.get(
                                    "arn", user_identity.get("userName", "N/A")
                                ),
                                "Source": TARGET_SERVICES[event_source],
                                "UsedEndpoint": used_endpoint,  # 엔드포인트 사용 여부 추가
                            }
                        )
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(
                        f"경고: 이벤트 처리 중 오류 발생 (EventId: {event.get('EventId')}): {e}"
                    )

        if not records:
            return f"인스턴스 ID '{instance_id}' 관련 대상 서비스({', '.join(TARGET_SERVICES.values())}) 이벤트를 찾을 수 없습니다 (최근 {time_value}{time_unit})."

        result_text = f"📄 *인스턴스 {instance_id} 관련 최근 이벤트 (최대 {max_results}개, 최근 {time_value}{time_unit}):*\n"
        sorted_records = sorted(
            records, key=lambda x: x.get("EventTime", ""), reverse=True
        )

        for i, rec in enumerate(sorted_records):
            if i >= max_results:
                result_text += f"\n... (결과가 너무 많아 {max_results}개만 표시)"
                break
            event_time_str = rec.get("EventTime", "N/A")
            try:
                dt_obj = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
                kst_time = dt_obj.astimezone(timezone(timedelta(hours=9)))
                time_formatted = kst_time.strftime("%Y-%m-%d %H:%M:%S KST")
            except:
                time_formatted = event_time_str

            # VPC 엔드포인트 사용 여부 포함하여 출력 (이모지 사용)
            endpoint_usage = rec.get("UsedEndpoint", "N/A")
            endpoint_emoji = "✅" if endpoint_usage == "Yes" else "❌"  # 이모지 결정
            endpoint_status = f"Endpoint 사용 여부: {endpoint_emoji}"  # 새로운 포맷
            result_text += f"- `{time_formatted}`: `{rec.get('EventName', 'N/A')}` ({endpoint_status}, User: `{rec.get('User', 'N/A')}`, Service: `{rec.get('Source', 'N/A')}`)\n"

        return result_text

    except client.exceptions.InvalidTimeRangeException:
        # 오류 메시지도 시간/일 단위 반영
        return f"오류: CloudTrail 조회 기간(최대 90일)이 잘못되었습니다. ({time_value}{time_unit})"
    except Exception as e:
        print(f"CloudTrail 조회/처리 중 오류 발생: {e}")
        return f"❌ CloudTrail 조회 중 오류가 발생했습니다: {e}"


# --- Slack 메시징 헬퍼 ---
def send_slack_message(response_url, text=None, blocks=None, replace_original=False):
    payload = {"response_type": "in_channel", "replace_original": replace_original}
    if text:
        # if len(text) > MAX_SLACK_MESSAGE_LENGTH:
        #     text = text[: MAX_SLACK_MESSAGE_LENGTH - 20] + "... (메시지 너무 김)"
        payload["text"] = text
    if blocks:
        payload["blocks"] = blocks
    try:
        response = requests.post(response_url, json=payload)
        response.raise_for_status()
        print(f"Slack 메시지 전송 성공. 응답: {response.text}")
        return True
    except requests.exceptions.RequestException as e:
        print(
            f"Slack 메시지 전송 실패: {e}. 응답 내용: {e.response.text if e.response else 'N/A'}"
        )
        return False
    except Exception as e:
        print(f"Slack 메시지 전송 중 예기치 않은 오류: {e}")
        return False


# --- Lambda 핸들러 ---
def lambda_handler(event, context):
    print("Lambda 실행 시작")
    print(f"event: {event}")

    # Case 2: 비동기 Lambda 호출 (내부 작업 단계) - 먼저 확인
    if "action" in event:
        action = event.get("action")
        response_url = event.get("response_url")
        instance_id = event.get("instance_id")
        region = event.get("region")
        print(f"비동기 작업 시작: {action}")

        # 비동기 호출 필수 파라미터 체크
        required_async_keys = ["action", "response_url", "instance_id", "region"]
        # 'execute_creation' 은 analysis_result 불필요, 'propose_creation'은 필요
        if action == "propose_creation" and "analysis_result" not in event:
            required_async_keys.append("analysis_result")
        elif action == "execute_creation" and not all(
            k in event for k in ["service", "vpc_id", "endpoint_type"]
        ):
            # execute_creation에 필요한 추가 키 확인
            required_async_keys.extend(["service", "vpc_id", "endpoint_type"])

        # 누락된 키 확인 개선
        missing_keys = [k for k in required_async_keys if not event.get(k)]
        if missing_keys:
            error_msg = (
                f"오류: 비동기 호출({action}) 필수 정보 누락: {', '.join(missing_keys)}"
            )
            print(f"{error_msg}. 수신 데이터: {event}")
            # response_url 이 있다면 오류 전송 시도
            if response_url:
                try:
                    send_slack_message(
                        response_url, text=f"❌ {error_msg}", replace_original=True
                    )
                except Exception:  # response_url 전송 실패는 무시
                    pass
            return {
                "statusCode": 400,
                "body": f"Missing required parameters for async call: {', '.join(missing_keys)}",
            }

        # --- 비동기 액션 처리 ---
        try:
            if action == "analyze_traffic":
                # ... analyze_traffic 로직 ...
                days = event.get("days")
                hours = event.get("hours")
                # CloudTrail 이벤트 조회 (유틸리티 함수 사용)
                # send_slack_message(...) # 시작 메시지는 초기 요청에서 보냄
                events_list = lookup_service_events_and_filter_by_instance(
                    region, instance_id, days=days, hours=hours
                )

                if not events_list:
                    send_slack_message(
                        response_url,
                        text=f"ℹ️ 인스턴스 '{instance_id}' 관련 대상 서비스 트래픽을 찾을 수 없습니다.",
                    )
                    return {"statusCode": 200, "body": "No relevant events found."}

                # 엔드포인트 사용 현황 분석 (유틸리티 함수 사용)
                potential_missing = analyze_endpoint_usage(events_list)
                print(
                    f"분석 결과 (미사용 {ENDPOINT_MISSING_THRESHOLD}회 이상): {potential_missing}"
                )

                if not potential_missing:
                    send_slack_message(
                        response_url,
                        text=f"✅ 분석 결과, 인스턴스 '{instance_id}' 트래픽에 대해 VPC 엔드포인트 생성이 필요한 경우가 감지되지 않았습니다.",
                        replace_original=True,  # 초기 메시지 대체
                    )
                else:
                    # 다음 단계 호출 (생성 제안)
                    send_slack_message(
                        response_url,
                        text="🔍 엔드포인트 생성 필요 가능성 발견. 자동 리소스 선택 및 생성 제안을 준비합니다...",
                        replace_original=True,  # 초기 메시지 대체
                    )
                    lambda_payload = {
                        "action": "propose_creation",
                        "response_url": response_url,
                        "instance_id": instance_id,
                        "region": region,
                        "analysis_result": potential_missing,
                    }
                    lambda_client.invoke(
                        FunctionName=SELF_FUNCTION_NAME,
                        InvocationType="Event",
                        Payload=json.dumps(lambda_payload).encode("utf-8"),
                    )
                    print(f"다음 단계(propose_creation) 호출: {lambda_payload}")

            elif action == "propose_creation":
                # ... propose_creation 로직 ...
                analysis_result = event.get("analysis_result")

                ec2_client = get_ec2_client(region)
                if not ec2_client:
                    raise Exception(f"EC2 클라이언트 생성 실패 ({region})")

                # 인스턴스 네트워크 정보 조회
                network_details = get_instance_network_details(region, instance_id)
                if not network_details:
                    raise Exception(f"인스턴스({instance_id}) 네트워크 정보 조회 실패")
                vpc_id = network_details["vpc_id"]
                instance_security_group_ids = network_details["security_group_ids"]

                # 최종적으로 보낼 블록 리스트 초기화
                final_blocks = []

                # 참조 인스턴스 정보를 첫 번째 블록으로 추가
                network_info_text = f"*참조 인스턴스 ({instance_id}) 정보:*\nVPC: `{vpc_id}`\n보안그룹: `{', '.join(instance_security_group_ids)}`"
                final_blocks.append(
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": network_info_text},
                    }
                )
                final_blocks.append({"type": "divider"})  # 구분선 추가

                for item in analysis_result:  # 리스트의 각 항목(딕셔너리) 순회
                    service = item.get("service")
                    rgn = item.get("region")
                    count = item.get("count")
                    if not service or not rgn or count is None:
                        print(f"경고: 분석 결과 항목 형식 오류 무시: {item}")
                        continue

                    if rgn != region:
                        continue  # 현재 리전만 처리
                    message_prefix = (
                        f"*제안 ({service} in {region}):* {count}회 미사용 감지\n"
                    )

                    # 서비스 타입 결정 및 서비스 이름 생성
                    endpoint_type = "Gateway" if service == "S3" else "Interface"
                    service_name_to_create = f"com.amazonaws.{region}.{service.lower() if service != 'ECR' else 'ecr.dkr'}"

                    # 기존 엔드포인트 확인
                    existing = check_existing_endpoint(
                        ec2_client, vpc_id, service_name_to_create
                    )
                    if existing:
                        warning_text = f"{message_prefix}⚠️ 이미 VPC `{vpc_id}`에 `{service_name_to_create}` 엔드포인트(`{existing[0]['VpcEndpointId']}`)가 존재하여 생성을 건너<0xEB><0x9B><0x81>니다."
                        final_blocks.append(
                            {
                                "type": "section",
                                "text": {"type": "mrkdwn", "text": warning_text},
                            }
                        )
                        final_blocks.append({"type": "divider"})
                        continue  # 다음 서비스 제안으로

                    # 생성 파라미터 준비
                    creation_params = {
                        "VpcEndpointType": endpoint_type,
                        "VpcId": vpc_id,
                        "ServiceName": service_name_to_create,
                        "TagSpecifications": [
                            {
                                "ResourceType": "vpc-endpoint",
                                "Tags": [
                                    {
                                        "Key": "Name",
                                        "Value": f"{vpc_id}-{service}-endpoint",
                                    },
                                    {
                                        "Key": "CreatedFromReferenceInstance",
                                        "Value": instance_id,
                                    },
                                ],
                            }
                        ],
                    }
                    selection_info = []

                    # 타입별 리소스 자동 선택
                    if endpoint_type == "Gateway":
                        route_table_ids, rt_info = select_route_tables_for_ha(
                            ec2_client, vpc_id
                        )
                        if not route_table_ids:
                            message_prefix += f"❌ {rt_info}\\n"  # 정보 추가
                        else:
                            creation_params["RouteTableIds"] = route_table_ids
                            selection_info.append(rt_info)
                    elif endpoint_type == "Interface":
                        subnet_ids, sn_info = select_subnets_for_ha(ec2_client, vpc_id)
                        if not subnet_ids:
                            message_prefix += f"❌ {sn_info}\\n"  # 정보 추가
                        else:
                            creation_params["SubnetIds"] = subnet_ids
                            selection_info.append(sn_info)
                        # 보안 그룹은 참조 인스턴스 것 사용
                        creation_params["SecurityGroupIds"] = (
                            instance_security_group_ids
                        )
                        creation_params["PrivateDnsEnabled"] = True

                    # 최종 제안 메시지 구성 (builds 'proposal_blocks')
                    proposal_blocks = [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": message_prefix + "\\n".join(selection_info),
                            },
                        }
                    ]

                    if "RouteTableIds" in creation_params or (
                        "SubnetIds" in creation_params
                        and "SecurityGroupIds" in creation_params
                    ):
                        # Block Kit 버튼 추가
                        button_value = {
                            "action": "confirm_creation",
                            "instance_id": instance_id,
                            "region": region,
                            "service": service,
                            "vpc_id": vpc_id,
                            "endpoint_type": endpoint_type,
                            "response_url": response_url,
                        }
                        try:
                            button_value_str = json.dumps(button_value)
                            if len(button_value_str) > 2000:
                                raise ValueError("Button value too long")

                            proposal_blocks.append(
                                {
                                    "type": "section",
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": f"위 정보로 *{service}* 엔드포인트 생성을 진행하시겠습니까?",
                                    },
                                }
                            )
                            proposal_blocks.append(
                                {
                                    "type": "actions",
                                    "elements": [
                                        {
                                            "type": "button",
                                            "text": {
                                                "type": "plain_text",
                                                "text": "✅ Yes, Create",
                                                "emoji": True,
                                            },
                                            "style": "primary",
                                            "value": button_value_str,
                                            "action_id": "create_endpoint_yes",
                                        },
                                        {
                                            "type": "button",
                                            "text": {
                                                "type": "plain_text",
                                                "text": "❌ No, Cancel",
                                                "emoji": True,
                                            },
                                            "style": "danger",
                                            "value": json.dumps(
                                                {"action": "cancel_creation"}
                                            ),
                                            "action_id": "create_endpoint_no",
                                        },
                                    ],
                                }
                            )
                        except ValueError as ve:
                            proposal_blocks.append(
                                {
                                    "type": "section",
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": f"❌ 버튼 생성 실패 (데이터 너무 김): {ve}. 수동 생성이 필요합니다.",
                                    },
                                }
                            )
                        except Exception as e:
                            proposal_blocks.append(
                                {
                                    "type": "section",
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": f"❌ 버튼 생성 중 오류: {e}",
                                    },
                                }
                            )
                    else:
                        proposal_blocks.append(
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": message_prefix
                                    + "-> 자동 리소스 선택 실패로 생성 제안 불가\\n",
                                },
                            }
                        )

                    # 완성된 proposal_blocks 를 final_blocks 에 확장 추가
                    final_blocks.extend(proposal_blocks)
                    # 버튼 있는 제안 뒤에만 구분선 추가
                    if proposal_blocks[-1].get("type") == "actions":
                        final_blocks.append({"type": "divider"})

                # 마지막 구분선 제거
                if final_blocks and final_blocks[-1].get("type") == "divider":
                    final_blocks.pop()

                if len(final_blocks) > 1:  # 초기 정보 블록 외에 내용이 있다면
                    # 합쳐진 모든 블록을 한 번에 전송 (replace_original 중요)
                    send_slack_message(
                        response_url, blocks=final_blocks, replace_original=True
                    )
                else:
                    # final_blocks가 초기 정보만 있는 경우
                    send_slack_message(
                        response_url,
                        text="처리할 엔드포인트 생성 제안이 없습니다. (이미 존재하거나 분석 결과 없음)",
                        replace_original=True,
                    )

            elif action == "execute_creation":
                # ... execute_creation 로직 ...
                service = event.get("service")
                vpc_id = event.get("vpc_id")
                endpoint_type = event.get("endpoint_type")

                try:
                    ec2_client = get_ec2_client(region)
                    if not ec2_client:
                        raise Exception(f"EC2 클라이언트 생성 실패 ({region})")

                    # 생성 파라미터 재구성
                    service_name_to_create = f"com.amazonaws.{region}.{service.lower() if service != 'ECR' else 'ecr.dkr'}"
                    creation_params = {
                        "VpcEndpointType": endpoint_type,
                        "VpcId": vpc_id,
                        "ServiceName": service_name_to_create,
                        "TagSpecifications": [
                            {
                                "ResourceType": "vpc-endpoint",
                                "Tags": [
                                    {
                                        "Key": "Name",
                                        "Value": f"{vpc_id}-{service}-endpoint",
                                    },
                                    {
                                        "Key": "CreatedFromReferenceInstance",
                                        "Value": instance_id,
                                    },
                                    {"Key": "Creator", "Value": "LambdaFunction"},
                                ],
                            }
                        ],
                    }

                    # 인스턴스 네트워크 정보 다시 조회
                    network_details = get_instance_network_details(region, instance_id)
                    if not network_details:
                        raise Exception(
                            f"참조 인스턴스 ({instance_id}) 네트워크 정보 재조회 실패"
                        )
                    instance_security_group_ids = network_details[
                        "security_group_ids"
                    ]  # 여기서 얻어야 함

                    # 타입별 리소스 자동 선택 및 파라미터 설정
                    if endpoint_type == "Gateway":
                        route_table_ids, rt_info = select_route_tables_for_ha(
                            ec2_client, vpc_id
                        )
                        if not route_table_ids:
                            raise Exception(f"라우트 테이블 자동 선택 실패: {rt_info}")
                        creation_params["RouteTableIds"] = route_table_ids
                    elif endpoint_type == "Interface":
                        subnet_ids, sn_info = select_subnets_for_ha(ec2_client, vpc_id)
                        if not subnet_ids:
                            raise Exception(f"서브넷 자동 선택 실패: {sn_info}")
                        creation_params["SubnetIds"] = subnet_ids
                        if not instance_security_group_ids:
                            raise Exception(
                                "참조 인스턴스의 보안 그룹 ID를 가져올 수 없음"
                            )
                        creation_params["SecurityGroupIds"] = (
                            instance_security_group_ids
                        )
                        creation_params["PrivateDnsEnabled"] = True
                    else:
                        raise ValueError(
                            f"지원하지 않는 엔드포인트 타입: {endpoint_type}"
                        )

                    print(
                        f"VPC 엔드포인트 생성 시도: {json.dumps(creation_params, indent=2)}"
                    )
                    response = ec2_client.create_vpc_endpoint(
                        **creation_params
                    )  # !!! 생성 실행 !!!

                    vpc_endpoint_info = response.get("VpcEndpoint", {})
                    new_endpoint_id = vpc_endpoint_info.get("VpcEndpointId")
                    current_state = vpc_endpoint_info.get("State")

                    if new_endpoint_id:
                        success_msg = f"✅ VPC 엔드포인트 생성을 요청했습니다.\nID: `{new_endpoint_id}`\n상태: `{current_state}` (pending 상태일 수 있습니다)"
                        print(success_msg)
                        send_slack_message(
                            response_url, text=success_msg, replace_original=True
                        )
                    else:
                        error_msg = "엔드포인트 생성 API 호출은 성공했으나, 응답에서 ID를 찾을 수 없습니다."
                        print(f"오류: {error_msg}. API 응답: {response}")
                        send_slack_message(
                            response_url, text=f"⚠️ {error_msg}", replace_original=True
                        )

                except Exception as e:
                    error_msg = f"엔드포인트 생성 실패: {e}"
                    print(f"오류: {error_msg}")
                    traceback.print_exc()
                    send_slack_message(
                        response_url, text=f"❌ {error_msg}", replace_original=True
                    )

            else:
                print(f"알 수 없는 action: {action}")
                send_slack_message(
                    response_url, text=f"오류: 알 수 없는 작업 요청 ({action})"
                )

        except Exception as e:
            error_msg = f"비동기 작업({action}) 처리 중 오류 발생: {e}"
            print(error_msg)
            traceback.print_exc()
            # 오류 발생 시에도 response_url로 알림 시도
            try:
                send_slack_message(
                    response_url, text=f"❌ {error_msg}", replace_original=True
                )
            except Exception:  # response_url 전송 실패는 무시
                pass

        return {"statusCode": 200, "body": f"Async action {action} completed."}

    # Case 1 & 3: Slack HTTP POST 요청 (Lambda Function URL)
    elif (
        event.get("requestContext", {}).get("http", {}).get("method") == "POST"
        and "body" in event
    ):
        try:
            body_str = event["body"]
            if event.get("isBase64Encoded", False):
                body_str = base64.b64decode(body_str).decode("utf-8")

            # application/x-www-form-urlencoded 형식 파싱
            parsed_body = parse_qs(body_str)

            # ** 구분 로직: 'payload' 키 유무 확인 **
            if "payload" in parsed_body:
                # Case 1: Block Kit Interaction
                payload_json_str = parsed_body.get("payload", [None])[0]
                if not payload_json_str:
                    raise ValueError(
                        "Form data에 payload 키가 없거나 값이 비어있습니다."
                    )
                slack_payload = json.loads(payload_json_str)
                response_url = slack_payload.get("response_url")

                if not response_url:
                    print("오류: 응답 URL이 없는 Slack 인터랙션")
                    return {"statusCode": 400, "body": "Missing response_url"}

                # 버튼 클릭 액션 처리
                if slack_payload.get("type") == "block_actions":
                    actions = slack_payload.get("actions", [])
                    if not actions:
                        print("경고: 빈 actions 배열")
                        return {"statusCode": 200, "body": ""}  # 빈 액션은 무시

                    action_info = actions[0]
                    action_id = action_info.get("action_id")
                    value_str = action_info.get("value")

                    if not action_id or not value_str:
                        print("오류: action_id 또는 value 누락")
                        send_slack_message(
                            response_url,
                            text="❌ 버튼 처리 중 오류 발생: 필수 정보 누락",
                        )
                        return {"statusCode": 400, "body": "Missing action_id or value"}

                    try:
                        value_data = json.loads(value_str)
                        button_action = value_data.get("action")

                        if (
                            action_id == "create_endpoint_yes"
                            and button_action == "confirm_creation"
                        ):
                            # 원본 메시지 즉시 업데이트
                            send_slack_message(
                                response_url,
                                text="⏳ VPC 엔드포인트 생성 요청 중...",
                                replace_original=True,
                            )
                            # execute_creation 액션 비동기 호출
                            lambda_payload = {
                                "action": "execute_creation",
                                "instance_id": value_data.get("instance_id"),
                                "region": value_data.get("region"),
                                "service": value_data.get("service"),
                                "vpc_id": value_data.get("vpc_id"),
                                "endpoint_type": value_data.get("endpoint_type"),
                                "response_url": value_data.get("response_url"),
                            }
                            required_keys = [
                                "instance_id",
                                "region",
                                "service",
                                "vpc_id",
                                "endpoint_type",
                                "response_url",
                            ]
                            if any(not lambda_payload.get(k) for k in required_keys):
                                raise ValueError(
                                    "execute_creation 호출을 위한 필수 파라미터 누락"
                                )

                            lambda_client.invoke(
                                FunctionName=SELF_FUNCTION_NAME,
                                InvocationType="Event",
                                Payload=json.dumps(lambda_payload).encode("utf-8"),
                            )
                            print(f"execute_creation 비동기 호출: {lambda_payload}")

                        elif (
                            action_id == "create_endpoint_no"
                            and button_action == "cancel_creation"
                        ):
                            send_slack_message(
                                response_url,
                                text="❌ 사용자가 VPC 엔드포인트 생성을 취소했습니다.",
                                replace_original=True,
                            )
                            print("사용자가 생성을 취소했습니다.")
                        else:
                            print(
                                f"알 수 없는 버튼 액션: action_id={action_id}, button_action={button_action}"
                            )
                            send_slack_message(
                                response_url, text="⚠️ 알 수 없는 버튼입니다."
                            )

                    except json.JSONDecodeError:
                        print(f"오류: 버튼 값 JSON 파싱 실패: {value_str}")
                        send_slack_message(
                            response_url,
                            text="❌ 버튼 처리 중 오류 발생: 데이터 형식 오류",
                        )
                        return {"statusCode": 400, "body": "Invalid value format"}
                    except ValueError as ve:
                        print(f"오류: {ve}")
                        send_slack_message(
                            response_url, text=f"❌ 버튼 처리 중 오류 발생: {ve}"
                        )
                        return {"statusCode": 400, "body": str(ve)}
                    except Exception as e:
                        print(f"버튼 액션 처리 중 예기치 않은 오류: {e}")
                        traceback.print_exc()
                        send_slack_message(
                            response_url, text=f"❌ 버튼 처리 중 예기치 않은 오류: {e}"
                        )
                        return {"statusCode": 500, "body": "Internal server error"}

                return {"statusCode": 200, "body": ""}  # ACK for block kit interaction

            elif "command" in parsed_body:
                # Case 3: Slash Command
                command = parsed_body.get("command", [None])[0]
                text = parsed_body.get("text", [""])[0].strip()
                response_url = parsed_body.get("response_url", [None])[0]
                user_id = parsed_body.get("user_id", [None])[0]  # 사용자 식별 필요 시

                if not command or not response_url:
                    print("오류: Slash command 필수 정보 누락 (command, response_url)")
                    return {
                        "statusCode": 400,
                        "body": "Missing command or response_url",
                    }

                print(f"Slash Command 요청 감지: {command} {text} (by {user_id})")

                # Slash command 파라미터 파싱
                instance_id_match = re.search(r"--instance-id\s+([\w-]+)", text)
                region_match = re.search(r"--region\s+([\w-]+)", text)
                days_match = re.search(r"--days\s+(\d+)", text)
                hours_match = re.search(r"--hours\s+(\d+)", text)
                instance_id = instance_id_match.group(1) if instance_id_match else None
                region = region_match.group(1) if region_match else None
                days = int(days_match.group(1)) if days_match else None
                hours = int(hours_match.group(1)) if hours_match else None
                time_unit, time_value = (
                    ("시간", hours)
                    if hours is not None
                    else (("일", days) if days is not None else ("일", 1))
                )
                if hours is None and days is None:
                    days = 1  # 기본값 설정

                if not instance_id or not region:
                    error_msg = (
                        "오류: `--instance-id`와 `--region`을 포함하여 입력해주세요."
                    )
                    # Slash command 오류는 ephemeral 응답
                    return {
                        "statusCode": 200,
                        "body": json.dumps(
                            {"response_type": "ephemeral", "text": error_msg}
                        ),
                        "headers": {"Content-Type": "application/json"},
                    }

                # 초기 응답 (in_channel) - Slash command는 3초 내 응답 필요 없으므로 바로 보내도 됨
                initial_response = f"---------\n🛠️ 인스턴스 '{instance_id}' ({region}) 관련 VPC 엔드포인트 분석을 시작합니다 (최근 {time_value}{time_unit})..."
                try:
                    requests.post(
                        response_url,
                        json={"response_type": "in_channel", "text": initial_response},
                    )
                except Exception as e:
                    print(f"Slack 초기 응답 실패: {e}")  # 실패해도 진행

                # 첫 분석 단계 비동기 호출
                lambda_payload = {
                    "action": "analyze_traffic",
                    "response_url": response_url,
                    "instance_id": instance_id,
                    "region": region,
                    "days": days,
                    "hours": hours,  # None 값도 그대로 전달
                }
                lambda_client.invoke(
                    FunctionName=SELF_FUNCTION_NAME,
                    InvocationType="Event",
                    Payload=json.dumps(lambda_payload).encode("utf-8"),
                )
                print(f"비동기 분석 호출: {lambda_payload}")

                # Slash command는 즉시 빈 body로 200 OK 응답 필요
                return {"statusCode": 200, "body": ""}

            else:
                # 'payload'도 'command'도 없는 POST 요청
                print("오류: 알 수 없는 POST 요청 형식")
                return {"statusCode": 400, "body": "Invalid POST request format"}

        except Exception as e:
            # HTTP POST 요청 처리 중 발생한 최상위 예외
            error_msg = f"HTTP POST 요청 처리 오류: {e}"
            print(error_msg)
            traceback.print_exc()
            # 에러 발생 시 response_url 이 있다면 ephemeral 메시지 시도
            response_url_in_exc = locals().get("response_url")
            if response_url_in_exc:
                try:
                    # Case 1/3 공통으로 ephemeral 로 오류 알림
                    requests.post(
                        response_url_in_exc,
                        json={
                            "response_type": "ephemeral",
                            "text": f"❌ 요청 처리 중 오류 발생: {e}",
                        },
                    )
                except Exception:
                    pass
            return {"statusCode": 500, "body": f"Error processing POST request: {e}"}

    else:
        # 비동기 호출도, Slack POST 요청도 아닌 경우 (예: 테스트 이벤트)
        print("알 수 없는 이벤트 유형 또는 GET 요청")
        # 필요하다면 다른 유형의 이벤트 처리 로직 추가
        return {"statusCode": 400, "body": "Unsupported event type or method"}
