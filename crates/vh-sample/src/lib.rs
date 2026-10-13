//! vh-sample: macOS 프로세스·메모리·포트 수집기 (CORE 소유).
//!
//! 공개 API는 [`CollectOptions`]와 [`collect`] 두 개다. 수집은 실패하지 않는다.
//! 부분 실패는 `Snapshot::collection_errors`에 남기고 값은 0으로 채우지 않는다.

use vh_model::Snapshot;

/// 수집 옵션.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectOptions {
    /// CPU 사용률용 두 번째 샘플 간격(밀리초). `None`이면 한 번만 샘플(`--no-cpu`).
    pub cpu_interval_ms: Option<u32>,
    /// `launchctl list`를 실행해 launchd 잡 PID를 채운다.
    pub launchd: bool,
    /// cwd에서 위로 올라가며 프로젝트 루트를 찾는다.
    pub project_roots: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        CollectOptions {
            cpu_interval_ms: Some(250),
            launchd: true,
            project_roots: true,
        }
    }
}

/// 이 맥의 현재 상태를 읽어 스냅샷을 만든다. 읽기 전용이며 패닉하지 않는다.
pub fn collect(opts: &CollectOptions) -> Snapshot {
    let _ = opts;
    unimplemented!("vh-sample 2b: 구현 중 (API 골격 커밋)")
}
