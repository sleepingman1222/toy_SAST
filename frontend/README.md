# Toy SAST Frontend

Toy SAST의 로그인, 프로젝트 관리, 분석 진행률, 취약점 결과 화면을 제공하는 React 애플리케이션입니다. 전체 프로젝트 실행 방법과 아키텍처는 루트의 [`README.md`](../README.md)를 참고하세요.

## 구성

```text
src/
├── api/          # HTTP client, 도메인별 API, 응답 정규화
├── auth/         # 인증 context와 access token 갱신
├── components/   # sidebar와 취약점 결과 UI
├── pages/        # 로그인 및 역할별 dashboard
└── utils/        # KISA 카탈로그 표시 유틸리티
```

개발 서버는 `/api` 요청을 Docker Compose의 `backend:8000`으로 전달합니다.

## 명령

```bash
npm install
npm run dev
npm run lint
npm run build
```
