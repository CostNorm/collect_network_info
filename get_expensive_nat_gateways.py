import boto3

ec2 = boto3.client(
    "ec2",
    region_name="ap-northeast-2",
)


def get_expensive_nat_gateways():
    response = ec2.describe_nat_gateways()
    expensive_nat_gateways = []

    for nat in response["NatGateways"]:
        nat_id = nat["NatGatewayId"]
        state = nat["State"]

        if state == "available":
            billing_data = boto3.client(
                "ce",
                region_name="ap-northeast-2",
            ).get_cost_and_usage(
                TimePeriod={"Start": "2024-03-01", "End": "2024-03-10"},
                Granularity="DAILY",
                Metrics=["UnblendedCost"],
                Filter={
                    "Dimensions": {
                        "Key": "SERVICE",
                        "Values": ["Amazon VPC NAT Gateway"],
                    }
                },
            )

            total_cost = sum(
                float(day["Total"]["UnblendedCost"]["Amount"])
                for day in billing_data["ResultsByTime"]
            )
            if total_cost > 1:
                expensive_nat_gateways.append((nat_id, total_cost))

    print("비용이 높은 NAT Gateway 목록:", expensive_nat_gateways)


if __name__ == "__main__":
    get_expensive_nat_gateways()
