import os
import boto3
import time
import random
import string
from datetime import datetime, timedelta


def generate_random_string(length=8):
    """랜덤 문자열 생성"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _run_ssm_command_and_wait(
    ssm_client, instance_id, commands, comment="Running SSM command"
):
    """SSM 명령어를 실행하고 완료될 때까지 기다린 후 결과를 반환합니다."""
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {comment}...")
    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": commands},
            Comment=comment,
        )
        command_id = response["Command"]["CommandId"]
        print(f"  Command ID: {command_id}")

        max_retries = 60  # 설치 시간을 고려하여 retry 증가 (5초 간격 * 60 = 5분)
        retry_count = 0
        final_result = None

        while retry_count < max_retries:
            try:
                result = ssm_client.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id
                )
                final_result = result
                if result["Status"] in ["Success", "Failed", "Cancelled", "TimedOut"]:
                    print(f"  상태: {result['Status']}")
                    if result.get("StandardOutputContent"):
                        print("  출력:")
                        print(result["StandardOutputContent"].strip())
                    if result.get("StandardErrorContent"):
                        print("  에러:")
                        print(result["StandardErrorContent"].strip())
                    return result["Status"] == "Success", result

                # Still running, wait before retrying
                time.sleep(5)  # 폴링 간격
                retry_count += 1
                # print(f"  명령어 실행 중... ({retry_count}/{max_retries})") # 상세 로그 필요 시 주석 해제

            except ssm_client.exceptions.InvocationDoesNotExist:
                print(
                    "  명령어 정보를 아직 사용할 수 없습니다. 잠시 후 다시 시도합니다."
                )
                time.sleep(2)
                # InvocationDoesNotExist 시 재시도 횟수를 증가시키지 않고 잠시 기다림
                continue
            except Exception as inner_e:
                print(f"  결과 확인 중 에러 발생: {str(inner_e)}")
                # Potentially break or retry depending on the error
                time.sleep(5)
                retry_count += 1

        print(f"  명령어 실행 시간 초과 또는 최대 재시도 도달 ({command_id})")
        return False, final_result  # 실패로 간주

    except Exception as e:
        print(f"  SSM 명령어 실행 중 에러 발생: {str(e)}")
        return False, None


def run_ecr_command(instance_id, duration_minutes=10, interval_seconds=30):
    """
    EC2 인스턴스에서 랜덤 도커 이미지를 생성하고 ECR에 푸시/풀하는 트래픽을 발생시키는 함수
    (시작 시 도커 설치 확인 및 자동 설치 포함)
    """
    ssm_client = boto3.client("ssm", region_name="ap-northeast-2")
    ecr_client = boto3.client("ecr", region_name="ap-northeast-2")
    sts_client = boto3.client("sts", region_name="ap-northeast-2")

    # --- Docker 설치 확인 및 설치 ---
    docker_install_commands = [
        "#!/bin/bash",
        "set -e",  # Exit immediately if a command exits with a non-zero status.
        "if ! command -v docker &> /dev/null",
        "then",
        "    echo 'Docker not found, attempting installation...'",
        "    export DEBIAN_FRONTEND=noninteractive",  # Prevent prompts during apt installs
        "    apt-get update -y",
        "    apt-get install -y ca-certificates curl gnupg lsb-release apt-transport-https software-properties-common",
        "    install -m 0755 -d /etc/apt/keyrings",
        "    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
        "    chmod a+r /etc/apt/keyrings/docker.gpg",
        '    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null',  # Corrected echo and tee command
        "    apt-get update -y",
        "    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
        # Add current user to docker group. Allow failure (e.g., if user already in group)
        "    usermod -aG docker $(whoami) || true",
        "    echo 'Docker installation attempt finished. Verification:'",
        "    docker --version",
        "    echo 'Note: You might need to start a new shell or log out/in for group changes to take effect for interactive use.'",
        "else",
        "    echo 'Docker is already installed. Verification:'",
        "    docker --version",
        "fi",
    ]
    print("--- 시작: 도커 설치 확인 및 설치 ---")
    success, _ = _run_ssm_command_and_wait(
        ssm_client, instance_id, docker_install_commands, "Checking/Installing Docker"
    )
    print("--- 완료: 도커 설치 확인 및 설치 ---")
    if not success:
        print("도커 설치 또는 확인에 실패했습니다. 스크립트를 종료합니다.")
        return
    # --- Docker 설치 완료 ---

    # ECR 리포지토리 이름 및 URI 설정
    repository_name = "random-docker-traffic"
    try:
        account_id = sts_client.get_caller_identity().get("Account")
        region = ecr_client.meta.region_name
        repository_uri = (
            f"{account_id}.dkr.ecr.{region}.amazonaws.com/{repository_name}"
        )

        print(f"ECR 리포지토리 확인/생성: {repository_name}")
        ecr_client.create_repository(repositoryName=repository_name)
        print(f"ECR 리포지토리 생성 성공 또는 이미 존재: {repository_name}")
    except ecr_client.exceptions.RepositoryAlreadyExistsException:
        print(f"ECR 리포지토리 이미 존재: {repository_name}")
        pass  # 이미 존재하면 정상 진행
    except Exception as e:
        print(f"ECR 리포지토리 생성/확인 중 에러: {e}")
        return

    # ECR 로그인 명령어 가져오기
    try:
        print("ECR 인증 토큰 가져오는 중...")
        auth_data = ecr_client.get_authorization_token()["authorizationData"][0]
        token = auth_data["authorizationToken"]
        # proxyEndpoint는 전체 URI (https:// 포함)
        proxy_endpoint = auth_data["proxyEndpoint"]
        # 로그인 명령어 생성 (전체 프록시 엔드포인트 사용)
        login_command = f"echo '{token}' | base64 -d | cut -d: -f2 | docker login -u AWS --password-stdin {proxy_endpoint}"
        print("ECR 로그인 명령어 준비 완료.")
    except Exception as e:
        print(f"ECR 인증 토큰 가져오기 실패: {e}")
        return

    # 실행 종료 시간 계산
    end_time = datetime.now() + timedelta(minutes=duration_minutes)

    print(f"\n스크립트 실행 시작 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"스크립트 실행 종료 시간: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"대상 EC2 인스턴스: {instance_id}")
    print(f"대상 ECR Repository URI: {repository_uri}")
    print(f"작업 간격: {interval_seconds} 초")

    push_toggle = True  # 푸시와 풀 번갈아가며 실행

    while datetime.now() < end_time:
        current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        loop_start_time = time.time()
        print(
            f"\n--- [{current_time_str}] 루프 시작 ({'Push' if push_toggle else 'Pull'}) ---"
        )
        try:
            # 랜덤 이미지 이름 생성
            image_name_local = (
                f"random-local-img-{generate_random_string()}"  # 로컬 빌드용 임시 이름
            )
            image_tag = generate_random_string()  # 태그도 랜덤 생성
            ecr_image_full_name = f"{repository_uri}:{image_tag}"

            # 기본 명령어 설정 (매번 ECR 로그인 포함)
            base_commands = [
                "echo '--- Logging in to ECR ---'",
                login_command,
                "echo '--- Docker Images Before Operation ---'",
                "docker images",  # 디버깅용
            ]

            operation_commands = []
            comment = ""

            if push_toggle:
                comment = f"Pushing {ecr_image_full_name}"
                print(f"→ 푸시 명령 준비: {ecr_image_full_name}")
                # 랜덤 도커 파일 내용 생성 (Python 문자열 내 줄바꿈은 \n 사용)
                dockerfile_content = (
                    f"FROM ubuntu:latest\n"
                    f"RUN echo 'Random content for {image_tag}: {generate_random_string(20)}' > /app/data.txt\n"
                    f"WORKDIR /app\n"
                    f'CMD ["cat", "/app/data.txt"]'  # CMD 배열 형식 주의
                )
                # 푸시 관련 명령어 추가
                operation_commands = [
                    f"echo '--- Building and Pushing {ecr_image_full_name} ---'",
                    f"TEMP_DIR=/tmp/{image_name_local}",
                    f"mkdir -p $TEMP_DIR",
                    # Dockerfile 내용 쓰기 (printf 사용하고 % 포맷팅 주의)
                    f"printf -- '{dockerfile_content.replace('%', '%%')}' > $TEMP_DIR/Dockerfile",  # Escape % for printf
                    f"echo 'Building local image {image_name_local}...' ",
                    f"docker build -t {image_name_local}:latest $TEMP_DIR",
                    f"echo 'Tagging image {image_name_local}:latest to {ecr_image_full_name}...' ",
                    f"docker tag {image_name_local}:latest {ecr_image_full_name}",
                    f"echo 'Pushing image {ecr_image_full_name}...' ",
                    f"docker push {ecr_image_full_name}",
                    f"echo 'Cleaning up local resources...' ",
                    f"docker rmi {image_name_local}:latest || echo 'Local build image already removed or failed to remove.'",  # 로컬 빌드 이미지 삭제
                    f"docker rmi {ecr_image_full_name} || echo 'Local ECR tagged image already removed or failed to remove.'",  # 로컬 ECR 태그 이미지 삭제
                    f"rm -rf $TEMP_DIR",
                    f"echo '--- Push completed for {ecr_image_full_name} ---'",
                ]

            else:
                comment = f"Pulling latest image from {repository_name}"
                print(f"→ 풀 명령 준비 (Latest image in {repository_name})")
                # 풀 관련 명령어 추가 (쉘 스크립트 구문 수정)
                operation_commands = [
                    f"echo '--- Pulling and Removing Latest Image from {repository_name} ---'",
                    # 가장 최근 푸시된 이미지 태그 가져오기
                    # Corrected: Use subshell and ensure proper quoting
                    f"LATEST_TAG=$(aws --no-cli-pager ecr describe-images --repository-name {repository_name} --query 'sort_by(imageDetails,& imagePushedAt)[-1].imageTags[0]' --output text --region {region} || echo \"\")",  # Added || echo to handle errors gracefully
                    f"echo 'Latest tag found: '$LATEST_TAG",
                    # 태그가 유효한 경우 풀 및 삭제 시도 (쉘 조건문 수정)
                    f'if [ -n "$LATEST_TAG" ] && [ "$LATEST_TAG" != "None" ] && [ "$LATEST_TAG" != "" ]; then '
                    f'  PULL_IMAGE_NAME="{repository_uri}:$LATEST_TAG"; '
                    f'  echo "Attempting to pull $PULL_IMAGE_NAME..."; '
                    f'  if docker pull "$PULL_IMAGE_NAME"; then '
                    f'    echo "Pull successful. Attempting to remove $PULL_IMAGE_NAME..."; '
                    f'    docker rmi "$PULL_IMAGE_NAME"; '
                    f'    echo "Image removed."; '
                    f"  else "
                    f'    echo "Failed to pull $PULL_IMAGE_NAME. Skipping removal."; '
                    f"  fi; "
                    f"else echo 'No valid tag found to pull or repository is empty.'; "
                    f"fi",  # End of if block
                    f"echo '--- Pull operation finished ---'",  # Corrected quote
                ]

            # 전체 명령어 조합 및 실행
            all_commands = base_commands + operation_commands
            success, _ = _run_ssm_command_and_wait(
                ssm_client, instance_id, all_commands, comment=comment
            )

            if not success:
                print(
                    f"ECR {'Push' if push_toggle else 'Pull'} 작업 중 오류가 발생했습니다. 다음 루프에서 계속합니다."
                )
                # 오류 발생 시에도 루프는 계속 돌도록 함 (일시적 네트워크 문제 등 고려)

            push_toggle = not push_toggle  # 다음 루프를 위해 토글

            # 작업 시간 계산 및 대기 시간 조정
            loop_end_time = time.time()
            elapsed_time = loop_end_time - loop_start_time
            wait_time = max(0, interval_seconds - elapsed_time)
            print(f"이번 루프 소요 시간: {elapsed_time:.2f} 초.")
            if wait_time > 0:
                print(f"다음 작업까지 {wait_time:.2f} 초 대기...")
                time.sleep(wait_time)
            else:
                print("작업 시간이 설정된 간격보다 길어 바로 다음 작업을 시작합니다.")

        except Exception as e:
            print(f"메인 루프에서 예외 발생: {str(e)}")
            print(f"오류 발생. {interval_seconds}초 후 다음 루프 시도...")
            time.sleep(interval_seconds)  # 에러 발생 시 기본 간격만큼 대기

    print(
        f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 지정된 시간({duration_minutes}분)이 경과하여 스크립트를 종료합니다."
    )


if __name__ == "__main__":
    # === 설정 값 ===
    TARGET_INSTANCE_ID = os.getenv("INSTANCE_ID")
    RUN_DURATION_MINUTES = 10  # 스크립트 총 실행 시간 (분)
    OPERATION_INTERVAL_SECONDS = 60  # 각 푸시/풀 작업 사이의 최소 간격 (초)
    # ===============

    if not TARGET_INSTANCE_ID or TARGET_INSTANCE_ID == "i-xxxxxxxxxxxxxxxxx":
        print("Error: TARGET_INSTANCE_ID를 실제 EC2 인스턴스 ID로 설정해주세요.")
    else:
        run_ecr_command(
            instance_id=TARGET_INSTANCE_ID,
            duration_minutes=RUN_DURATION_MINUTES,
            interval_seconds=OPERATION_INTERVAL_SECONDS,
        )  # Corrected closing parenthesis
