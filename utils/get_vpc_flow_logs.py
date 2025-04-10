import boto3
import requests
import ipaddress
import socket
import os

# ===============================
# 1. AWS 클라이언트 생성
# ===============================
logs_client = boto3.client("logs", region_name="ap-northeast-2")
ec2_client = boto3.client("ec2", region_name="ap-northeast-2")

LOG_GROUP_NAME = os.getenv("LOG_GROUP_NAME")
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


# ===============================
# 2. NAT Gateway의 ENI ID 가져오기
# ===============================
def get_nat_gateway_enis():
    """NAT Gateway에 연결된 ENI ID 목록을 가져오는 함수"""
    response = ec2_client.describe_nat_gateways()
    eni_ids = []

    for nat_gateway in response["NatGateways"]:
        for address in nat_gateway.get("NatGatewayAddresses", []):
            eni_id = address.get("NetworkInterfaceId")
            if eni_id:
                eni_ids.append(eni_id)

    return eni_ids


# NAT Gateway ENI 목록 가져오기
nat_eni_ids = get_nat_gateway_enis()
print(f"NAT Gateway ENI IDs: {nat_eni_ids}")


# ===============================
# 3. AWS 서비스별 IP 대역 가져오기
# ===============================
def get_aws_ip_ranges():
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    response = requests.get(url)
    ip_ranges = response.json()

    aws_ip_ranges = {}
    for prefix in ip_ranges["prefixes"]:
        service = prefix.get("service", "UNKNOWN")
        ip_prefix = prefix["ip_prefix"]

        if service not in aws_ip_ranges:
            aws_ip_ranges[service] = []
        aws_ip_ranges[service].append(ip_prefix)

    return aws_ip_ranges


aws_services = get_aws_ip_ranges()


# ===============================
# 4. Reverse DNS 조회
# ===============================
def reverse_dns_lookup(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except Exception:
        return "Unknown"


# ===============================
# 5. NAT Gateway 트래픽 로그 조회 및 분석 (interface-id 기준)
# ===============================
def get_nat_gateway_logs(log_group_name, nat_eni_ids):
    response = logs_client.describe_log_streams(logGroupName=log_group_name)

    for log_stream in response["logStreams"]:
        log_stream_name = log_stream["logStreamName"]

        log_events = logs_client.get_log_events(
            logGroupName=log_group_name, logStreamName=log_stream_name, limit=500
        )

        for event in log_events["events"]:
            log_parts = event["message"].split()

            if len(log_parts) < 5:
                continue

            interface_id = log_parts[2]
            src_ip = log_parts[3]
            dst_ip = log_parts[4]

            # NAT Gateway와 연결된 ENI ID인지 확인
            if interface_id in nat_eni_ids:
                service_name = check_aws_service(dst_ip)

                # 서비스가 Unknown이 아닌 경우에만 처리
                if service_name != "Unknown":
                    reverse_dns = reverse_dns_lookup(dst_ip)
                    # 서비스와 DNS 모두 Unknown이 아닌 경우에만 출력
                    if reverse_dns != "Unknown":
                        print(
                            f"[NAT-GW ENI: {interface_id}] {src_ip} -> {dst_ip} | AWS: {service_name} | DNS: {reverse_dns}"
                        )
                        check_internal_service_usage(src_ip, dst_ip)


# ===============================
# 6. AWS 서비스 IP 매칭
# ===============================
def check_aws_service(ip):
    # IP가 '-'인 경우 처리
    if ip == "-":
        return "Unknown"

    ip_obj = ipaddress.ip_address(ip)
    for service, ip_list in aws_services.items():
        for ip_range in ip_list:
            if ip_obj in ipaddress.ip_network(ip_range):
                return service

    reverse_dns = reverse_dns_lookup(ip)
    if ".amazonaws.com" in reverse_dns:
        return reverse_dns.split(".")[0]

    return "Unknown"


# ===============================
# 7. 내부 서비스가 NAT GW 경유 여부 확인
# ===============================
def check_internal_service_usage(src_ip, dst_ip):
    # IP가 '-'인 경우 처리
    if src_ip == "-" or dst_ip == "-":
        return

    src_ip_obj = ipaddress.ip_address(src_ip)
    dst_ip_obj = ipaddress.ip_address(dst_ip)

    is_src_internal = any(src_ip_obj in network for network in PRIVATE_IP_RANGES)
    is_dst_internal = any(dst_ip_obj in network for network in PRIVATE_IP_RANGES)

    # 목적지 IP의 서비스 확인
    service_name = check_aws_service(dst_ip)

    # 내부에서 외부로 나가는 트래픽이고, Unknown이 아닌 경우에만 출력
    if is_src_internal and not is_dst_internal and service_name != "Unknown":
        print(
            f"⚠️ 내부 서비스 {src_ip} 가 NAT Gateway를 통해 {dst_ip} 로 트래픽을 전송 중!"
        )


# 실행
get_nat_gateway_logs(LOG_GROUP_NAME, nat_eni_ids)
