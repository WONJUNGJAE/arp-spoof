# arp-spoof

## !!교수님 필독 부탁드립니다!!
현재 영상에서 패킷이 4개가 아닌 총 5개가 잡히는데 교수님 ppt 12장에서 최신 os가 자신에게 오면 안되는 패킷을 자동으로 한번 더 relay한다
이 내용이 잡혔습니다( 친구 victim 컴퓨터에서 ping으로 1개 보낼때 정상적으로 loss 없이 답장이 온거까지 확인이 되었고 과제 의도대로 총 4개의 패킷이 잡혔는데 wireshark에서 지금 영상속 18번 패킷(즉 하나 더 온거 그거) 을 분석해보니 지금 17번 패킷과 완전 동일한데 대신에 ttl만 1개 더 차이나는게 보였습니다 (17번 패킷은 정상적인 Attacker -> gateway로 relay request 인데 이건 제 코드 에서 보내진거고 18번 패킷은 똑같은 Attacker -> gateway relay request 인데 os커널이 보낸 relay request입니다) 


## 실습 환경

| 역할 | IP |
|------|----|
| Attacker (내 컴퓨터) | 192.168.26.249 |
| Sender (친구 컴퓨터) | 192.168.26.223 |
| Gateway (핫스팟) | 192.168.26.209 |

## 실행영상
https://private-user-images.githubusercontent.com/210666361/578039862-f4d0a50a-330e-4b8d-87cb-a5b5b0c9a83c.mp4?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NzYxNzcwNjgsIm5iZiI6MTc3NjE3Njc2OCwicGF0aCI6Ii8yMTA2NjYzNjEvNTc4MDM5ODYyLWY0ZDBhNTBhLTMzMGUtNGI4ZC04N2NiLWE1YjViMGM5YTgzYy5tcDQ_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjYwNDE0JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI2MDQxNFQxNDI2MDhaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1lMzAxYTRiNTFjNGFkN2ZiNGM5MzE2OTlkOWUwMWUxZjY2NDU5MzcwMzlmZWU5NDJjYTFjNGQzOWI2MzNiNzRmJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCZyZXNwb25zZS1jb250ZW50LXR5cGU9dmlkZW8lMkZtcDQifQ.pooSaQid3L-fHeMzS9W_iOkPuK5NMHBlLCyq5JuakFE
