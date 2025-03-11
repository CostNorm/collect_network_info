import boto3

ec2 = boto3.client(
    "ec2",
    region_name="ap-northeast-2",
)


def analyze_nat_dependencies(nat_gateway_id):
    route_tables = ec2.describe_route_tables()
    nat_dependencies = []

    for rt in route_tables["RouteTables"]:
        for route in rt["Routes"]:
            if route.get("NatGatewayId") == nat_gateway_id:
                subnet_id = route.get("SubnetId", "Unknown")
                nat_dependencies.append((rt["RouteTableId"], subnet_id))

    print(
        f"📌 NAT Gateway {nat_gateway_id} 관련 서브넷 및 라우팅 테이블:",
        nat_dependencies,
    )


# 특정 NAT Gateway 종속성 분석
analyze_nat_dependencies()
