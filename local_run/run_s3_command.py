import boto3
import time
from datetime import datetime, timedelta
import os


def run_s3_command(instance_id, bucket_name, duration_minutes=10, interval_seconds=30):
    """
    EC2 인스턴스에서 S3 명령어와 업로드/다운로드를 주기적으로 실행하는 함수

    Args:
        instance_id (str): EC2 인스턴스 ID
        duration_minutes (int): 실행 시간 (분)
        interval_seconds (int): 명령어 실행 간격 (초)
    """
    ssm_client = boto3.client("ssm", region_name="ap-northeast-2")

    # 실행 종료 시간 계산
    end_time = datetime.now() + timedelta(minutes=duration_minutes)

    print(f"시작 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"종료 시간: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")

    upload_toggle = True  # 업로드와 다운로드 번갈아가며 실행

    while datetime.now() < end_time:
        try:
            # 1. aws s3 ls
            commands = ["aws s3 ls"]

            # 2. 업로드 or 다운로드 (매 실행마다 번갈아 수행)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            test_filename = f"test_{timestamp}.txt"
            local_file_path = f"/tmp/{test_filename}"

            if upload_toggle:
                # 업로드용 로컬 파일 생성 + 업로드
                commands += [
                    f"echo 'Test file created at {timestamp}' > {local_file_path}",
                    f"aws s3 cp {local_file_path} s3://{bucket_name}/{test_filename}",
                ]
                print(f"→ 업로드 명령 준비: {test_filename}")
            else:
                # 다운로드 (기존 파일을 하나 선택해 다운로드 시도)
                commands += [
                    f"aws s3 ls s3://{bucket_name}/ | tail -n 1 | awk '{{print $4}}' > /tmp/last_file.txt",
                    f"LAST_FILE=$(cat /tmp/last_file.txt)",
                    f"aws s3 cp s3://{bucket_name}/$LAST_FILE /tmp/$LAST_FILE",
                ]
                print(f"→ 다운로드 명령 준비")

            upload_toggle = not upload_toggle  # 다음엔 반대 작업

            # 명령어 실행
            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": commands},
            )

            command_id = response["Command"]["CommandId"]
            print(
                f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 명령어 실행 중..."
            )

            # 실행 결과 확인
            max_retries = 30
            retry_count = 0

            while retry_count < max_retries:
                try:
                    result = ssm_client.get_command_invocation(
                        CommandId=command_id, InstanceId=instance_id
                    )

                    if result["Status"] in ["Success", "Failed", "Cancelled"]:
                        print(f"상태: {result['Status']}")
                        if result.get("StandardOutputContent"):
                            print("출력:")
                            print(result["StandardOutputContent"])
                        if result.get("StandardErrorContent"):
                            print("에러:")
                            print(result["StandardErrorContent"])
                        break

                    time.sleep(1)
                    retry_count += 1

                except ssm_client.exceptions.InvocationDoesNotExist:
                    print("명령어 실행 중... 잠시만 기다려주세요.")
                    time.sleep(1)
                    retry_count += 1
                    continue

            if retry_count >= max_retries:
                print("명령어 실행 시간 초과")

            time.sleep(interval_seconds)

        except Exception as e:
            print(f"에러 발생: {str(e)}")
            time.sleep(interval_seconds)


if __name__ == "__main__":
    INSTANCE_ID = os.getenv("INSTANCE_ID")
    BUCKET_NAME = os.getenv("BUCKET_NAME")
    run_s3_command(
        instance_id=INSTANCE_ID,
        bucket_name=BUCKET_NAME,
        duration_minutes=10,
        interval_seconds=30,
    )
