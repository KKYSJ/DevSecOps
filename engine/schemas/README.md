# Engine Schemas

이 디렉터리는 `engine/`에서 사용하는 공통 스키마와 정규화 기준을 위한 자리입니다.

## 역할

- 도구별 raw 결과를 공통 구조로 해석할 때 기준점 제공
- 파싱 결과와 리포트 데이터를 같은 형태로 다루기 위한 보조 문서 역할

## 참고

실제 파싱 / 정규화 / 리포트 로직은 아래 디렉터리에서 동작합니다.

- `engine/parsers`
- `engine/normalizer`
- `engine/reporting`

현재 저장소에서는 코드가 문서보다 우선 소스 오브 트루스이며, 상세 흐름은 루트 README와 `docs/architecture/` 문서를 함께 보는 편이 좋습니다.
