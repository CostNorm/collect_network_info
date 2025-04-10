import boto3
from datetime import datetime, timedelta
from pprint import pprint

ec2 = boto3.client(
    "ec2",
    region_name="ap-northeast-2",
)


def get_expensive_nat_gateways():
    response = ec2.describe_nat_gateways()
    expensive_nat_gateways = []

    # 날짜 계산 (최근 30일)
    end_date = datetime.today().strftime("%Y-%m-%d")
    start_date = (datetime.today() - timedelta(days=30)).strftime("%Y-%m-%d")

    for nat in response["NatGateways"]:
        nat_id = nat["NatGatewayId"]
        state = nat["State"]

        if state == "available":
            billing_data = boto3.client(
                "ce",
                region_name="ap-northeast-2",
            ).get_cost_and_usage(
                TimePeriod={"Start": start_date, "End": end_date},
                Granularity="DAILY",  # MONTHLY에서 DAILY로 변경
                Metrics=["UnblendedCost"],
                Filter={
                    "And": [
                        {
                            "Dimensions": {
                                "Key": "SERVICE",
                                "Values": ["EC2 - Other"],
                            }
                        },
                        {
                            "Dimensions": {
                                "Key": "OPERATION",
                                "Values": ["NatGateway"],
                            }
                        },
                    ]
                },
            )

            print("\n")
            pprint(billing_data)

            # 일별 비용 계산 및 합산
            daily_costs = []
            for day in billing_data["ResultsByTime"]:
                date = day["TimePeriod"]["Start"]
                cost = float(day["Total"]["UnblendedCost"]["Amount"])
                if cost > 0:
                    daily_costs.append({"date": date, "cost": round(cost, 5)})

            total_cost = sum(day["cost"] for day in daily_costs)

            if total_cost > 0:
                expensive_nat_gateways.append(
                    {
                        "nat_id": nat_id,
                        "total_cost": round(total_cost, 5),
                        "daily_costs": daily_costs,
                    }
                )

    if expensive_nat_gateways:
        print("\n비용이 발생한 NAT Gateway 목록:")
        for nat in expensive_nat_gateways:
            print(f"\nNAT Gateway ID: {nat['nat_id']}")
            print(f"총 비용: ${nat['total_cost']}")
            print("일별 비용:")
            for daily in nat["daily_costs"]:
                print(f"  {daily['date']}: ${daily['cost']}")
    else:
        print("\n비용이 발생한 NAT Gateway가 없습니다.")

    # 디버깅을 위한 정보 출력
    print("\n마지막 Cost Explorer 응답:")


if __name__ == "__main__":
    get_expensive_nat_gateways()
