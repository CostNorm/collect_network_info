import boto3
import pandas as pd
from datetime import datetime, timedelta

ce = boto3.client(
    "ce",
    region_name="ap-northeast-2",
)


def get_service_operation_cost():
    start_date = (datetime.today() - timedelta(days=30)).strftime("%Y-%m-%d")
    end_date = datetime.today().strftime("%Y-%m-%d")
    response = ce.get_cost_and_usage(
        TimePeriod={"Start": start_date, "End": end_date},
        Granularity="DAILY",
        Metrics=["UnblendedCost"],
        GroupBy=[
            {"Type": "DIMENSION", "Key": "SERVICE"},  # 서비스별 그룹화
            {"Type": "DIMENSION", "Key": "OPERATION"},  # 세부 기능(연산)별 그룹화
        ],
    )

    cost_data = []
    for day in response["ResultsByTime"]:
        for group in day["Groups"]:
            service_name = group["Keys"][0]
            operation = group["Keys"][1]  # 세부 기능
            cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
            cost_data.append((service_name, operation, cost))

    df = pd.DataFrame(cost_data, columns=["Service", "Operation", "Cost"])
    print("AWS 서비스별 세부 기능 비용:")
    print(df)


# 실행
get_service_operation_cost()
