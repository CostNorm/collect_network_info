import boto3
import pandas as pd
from datetime import datetime, timedelta

ce = boto3.client(
    "ce",
    region_name="ap-northeast-2",
)


def get_service_cost():
    start_date = (datetime.today() - timedelta(days=30)).strftime("%Y-%m-%d")
    end_date = datetime.today().strftime("%Y-%m-%d")

    response = ce.get_cost_and_usage(
        TimePeriod={"Start": start_date, "End": end_date},
        Granularity="DAILY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )

    cost_data = []
    for day in response["ResultsByTime"]:
        for group in day["Groups"]:
            service_name = group["Keys"][0]
            cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
            cost_data.append((service_name, cost))

    df = pd.DataFrame(cost_data, columns=["Service", "Cost"])
    print("AWS 서비스별 비용:")
    print(df)


if __name__ == "__main__":
    get_service_cost()
