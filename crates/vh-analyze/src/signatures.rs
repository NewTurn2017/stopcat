//! 도감: 정적 분류 표. 실행 중 외부 파일을 읽지 않는다.
//!
//! 평가 순서: priority 오름차순(표가 이미 그 순서로 정렬돼 있다), 첫 매칭 행이 이긴다.
//! `outside_bundle` 행은 출처가 `AppBundle`이면 건너뛴다(앱 내장 런타임이 개발 도구로 잘못 잡히지 않게).
//! Homebrew·Xcode `Python.app`과 Xcode `Contents/Developer`는 `exe_origin`이 `DevToolBundle`로 주므로
//! 번들 구조 행(AppHelper·GuiApp)에 닿기 전에 argv로 분류된다.

use vh_model::{ExeOrigin, Kind, Proc};

use crate::features::{Feat, Interp, token_base};
use crate::fmt::safe;

#[derive(Debug)]
pub(crate) enum C {
    PidEq(i32),
    ExePrefix(&'static [&'static str]),
    NotExePrefix(&'static [&'static str]),
    ExeContains(&'static str),
    ExeSuffix(&'static str),
    ExeBase(&'static str),
    ExeBaseAny(&'static [&'static str]),
    ExeBasePrefix(&'static str),
    NameEq(&'static str),
    TitlePrefix(&'static str),
    InterpIs(Interp),
    EntryContains(&'static str),
    EntrySuffix(&'static str),
    NameBase(&'static str),
    NameBaseAny(&'static [&'static str]),
    Module(&'static str),
    SubAny(&'static [&'static str]),
    Token(&'static str),
    TokenAny(&'static [&'static str]),
    TokenSeq(&'static str, &'static str),
    TokenContains(&'static str),
    TokenPrefixAny(&'static [&'static str]),
    TokenSuffixAny(&'static [&'static str]),
    TokenBaseContains(&'static str),
    TokenBasePrefix(&'static str),
    TokenBaseSuffixAny(&'static [&'static str]),
    NotTokenAny(&'static [&'static str]),
    ChromiumExe,
    InBinDir,
    EnvIn(&'static str, &'static [&'static str]),
    EnvHas(&'static str),
    BundleMain,
    InAppBundlePath,
    AgentEntry(&'static str),
    All(&'static [C]),
    Any(&'static [C]),
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Any,
    OutsideBundle,
}

#[derive(Debug)]
pub(crate) struct Signature {
    pub id: &'static str,
    pub kind: Kind,
    pub priority: u8,
    pub scope: Scope,
    pub cond: C,
    pub label: &'static str,
}

const fn sig(
    id: &'static str,
    kind: Kind,
    priority: u8,
    scope: Scope,
    cond: C,
    label: &'static str,
) -> Signature {
    Signature {
        id,
        kind,
        priority,
        scope,
        cond,
        label,
    }
}

use C::*;
use Kind as K;
use Scope::{Any as A, OutsideBundle as O};

const CHROMIUM_BASES: &[&str] = &[
    "Google Chrome",
    "Google Chrome for Testing",
    "Chromium",
    "Microsoft Edge",
    "Brave Browser",
    "chrome",
    "chromium",
    "chrome-headless-shell",
];

pub(crate) const SIGNATURES: &[Signature] = &[
    sig(
        "sys_launchd",
        K::System,
        0,
        A,
        PidEq(1),
        "launchd(모든 프로세스의 뿌리)",
    ),
    sig(
        "sys_controlcenter",
        K::System,
        1,
        A,
        ExeSuffix("/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"),
        "제어 센터(AirPlay 수신 포함)",
    ),
    sig(
        "sys_system",
        K::System,
        2,
        A,
        ExePrefix(&["/System/"]),
        "macOS 시스템 구성요소",
    ),
    sig(
        "sys_libexec",
        K::System,
        2,
        A,
        ExePrefix(&["/usr/libexec/"]),
        "macOS 시스템 서비스",
    ),
    sig(
        "sys_sbin",
        K::System,
        2,
        A,
        ExePrefix(&["/usr/sbin/", "/sbin/"]),
        "macOS 시스템 데몬",
    ),
    sig(
        "sys_library_apple",
        K::System,
        2,
        A,
        ExePrefix(&["/Library/Apple/"]),
        "macOS 시스템 구성요소",
    ),
    sig(
        "emu_sim_runtime",
        K::Emulator,
        3,
        A,
        Any(&[
            ExePrefix(&["/Library/Developer/CoreSimulator/"]),
            NameEq("launchd_sim"),
            ExeBase("launchd_sim"),
        ]),
        "iOS 시뮬레이터 내부 프로세스",
    ),
    sig(
        "sys_developer_private",
        K::System,
        3,
        A,
        ExePrefix(&["/Library/Developer/PrivateFrameworks/"]),
        "Xcode 개발 도구 서비스",
    ),
    sig(
        "agent_codex_app_server",
        K::AgentHelper,
        10,
        O,
        All(&[AgentEntry("codex"), Token("app-server")]),
        "codex 앱 서버(백엔드)",
    ),
    sig(
        "agent_codex_code_mode_host",
        K::AgentHelper,
        10,
        O,
        ExeBase("codex-code-mode-host"),
        "codex 코드 실행 도우미",
    ),
    sig(
        "agent_claude_bg",
        K::AgentHelper,
        10,
        O,
        Any(&[
            TitlePrefix("claude bg-"),
            TokenAny(&["--bg-spare", "--bg-pty-host"]),
        ]),
        "Claude 예비 세션",
    ),
    sig(
        "agent_claude_daemon",
        K::AgentHelper,
        10,
        O,
        All(&[AgentEntry("claude"), SubAny(&["daemon"])]),
        "Claude 백그라운드 데몬",
    ),
    sig(
        "agent_codex_broker",
        K::AgentHelper,
        10,
        O,
        All(&[
            EntryContains("/openai-codex/"),
            NameBase("app-server-broker"),
        ]),
        "codex 앱 서버 중계(브로커)",
    ),
    sig(
        "agent_omo_py_kernel",
        K::AgentHelper,
        10,
        O,
        All(&[
            InterpIs(Interp::Python),
            Any(&[
                EntryContains("/senpi-codemode/src/kernels/"),
                EnvHas("SENPI_PY_KERNEL_PARENT_PID"),
            ]),
        ]),
        "omo 파이썬 커널",
    ),
    sig(
        "agent_omo_lsp_daemon",
        K::LanguageServer,
        10,
        O,
        EntryContains("/omo-ai/plugin/runtime/lsp-daemon/"),
        "omo 언어 서버 데몬",
    ),
    sig(
        "mcp_chrome_devtools",
        K::McpServer,
        20,
        A,
        TokenContains("chrome-devtools-mcp"),
        "MCP 서버: chrome-devtools",
    ),
    sig(
        "mcp_xcodebuild",
        K::McpServer,
        20,
        A,
        TokenBaseContains("xcodebuildmcp"),
        "MCP 서버: XcodeBuild",
    ),
    sig(
        "mcp_convex",
        K::McpServer,
        20,
        A,
        TokenSeq("convex", "mcp"),
        "MCP 서버: Convex",
    ),
    sig(
        "mcp_modelcontextprotocol",
        K::McpServer,
        20,
        A,
        TokenContains("@modelcontextprotocol/server-"),
        "MCP 서버: {mcp_name}",
    ),
    sig(
        "mcp_server_prefix",
        K::McpServer,
        21,
        A,
        TokenBasePrefix("mcp-server-"),
        "MCP 서버: {mcp_name}",
    ),
    sig(
        "mcp_name_suffix",
        K::McpServer,
        21,
        A,
        TokenBaseSuffixAny(&["-mcp", "_mcp"]),
        "MCP 서버: {mcp_name}",
    ),
    sig(
        "mcp_extra_spec",
        K::McpServer,
        21,
        A,
        TokenContains("[mcp]"),
        "MCP 서버: {mcp_name}",
    ),
    sig(
        "mcp_subcommand",
        K::McpServer,
        22,
        A,
        SubAny(&["mcp", "mcp-server"]),
        "MCP 서버: {entry_name}",
    ),
    sig(
        "agent_claude_native",
        K::AgentCli,
        30,
        O,
        AgentEntry("claude"),
        "Claude Code 세션",
    ),
    sig(
        "agent_omo",
        K::AgentCli,
        30,
        O,
        Any(&[
            All(&[
                InterpIs(Interp::Bun),
                EntryContains("/senpi/"),
                EntrySuffix("cli.js"),
            ]),
            EntrySuffix("/omo-ai/bin/omo.js"),
        ]),
        "omo 세션",
    ),
    sig(
        "agent_codex",
        K::AgentCli,
        31,
        O,
        AgentEntry("codex"),
        "Codex 세션",
    ),
    sig(
        "hb_chrome_for_testing",
        K::HeadlessBrowser,
        40,
        A,
        ExeContains("Google Chrome for Testing.app/"),
        "자동화용 Chrome(Chrome for Testing)",
    ),
    sig(
        "hb_headless_shell",
        K::HeadlessBrowser,
        40,
        A,
        ExeBase("chrome-headless-shell"),
        "헤드리스 Chrome",
    ),
    sig(
        "hb_playwright",
        K::HeadlessBrowser,
        40,
        A,
        ExeContains("/ms-playwright/"),
        "Playwright 브라우저",
    ),
    sig(
        "hb_puppeteer",
        K::HeadlessBrowser,
        40,
        A,
        ExeContains("/.cache/puppeteer/"),
        "Puppeteer 브라우저",
    ),
    sig(
        "hb_flag_headless",
        K::HeadlessBrowser,
        41,
        A,
        All(&[ChromiumExe, TokenPrefixAny(&["--headless"])]),
        "헤드리스 브라우저",
    ),
    sig(
        "hb_flag_remote_debug",
        K::HeadlessBrowser,
        42,
        O,
        All(&[
            ChromiumExe,
            TokenPrefixAny(&["--remote-debugging-port", "--remote-debugging-pipe"]),
            NotExePrefix(&["/Applications/"]),
        ]),
        "원격 조종 브라우저",
    ),
    sig(
        "emu_qemu_android",
        K::Emulator,
        42,
        O,
        All(&[
            ExeBasePrefix("qemu-system-"),
            Any(&[Token("-avd"), ExeContains("/Android/sdk/")]),
        ]),
        "Android 에뮬레이터(qemu)",
    ),
    sig(
        "emu_android_emulator",
        K::Emulator,
        42,
        O,
        All(&[ExeBase("emulator"), Token("-avd")]),
        "Android 에뮬레이터",
    ),
    sig(
        "emu_android_aux",
        K::Emulator,
        42,
        O,
        All(&[
            ExeContains("/Android/sdk/emulator/"),
            ExeBaseAny(&["netsimd", "crashpad_handler"]),
        ]),
        "Android 에뮬레이터 도우미",
    ),
    sig(
        "emu_ios_simulator_app",
        K::Emulator,
        42,
        A,
        ExeSuffix("/Simulator.app/Contents/MacOS/Simulator"),
        "iOS 시뮬레이터 앱",
    ),
    sig(
        "vm_orbstack",
        K::VirtualMachine,
        42,
        A,
        All(&[
            ExeContains("/OrbStack.app/"),
            Any(&[
                Token("vmgr"),
                NameEq("OrbStack Helper"),
                ExeBase("OrbStack Helper"),
            ]),
        ]),
        "OrbStack 가상 머신",
    ),
    sig(
        "vm_docker",
        K::VirtualMachine,
        42,
        A,
        Any(&[
            ExeBasePrefix("com.docker."),
            ExeContains("/Docker.app/Contents/MacOS/com.docker"),
        ]),
        "Docker Desktop 가상 머신",
    ),
    sig(
        "vm_lima",
        K::VirtualMachine,
        42,
        O,
        ExeBaseAny(&["colima", "limactl"]),
        "Colima/Lima 가상 머신",
    ),
    sig(
        "vm_qemu_generic",
        K::VirtualMachine,
        42,
        O,
        ExeBasePrefix("qemu-system-"),
        "QEMU 가상 머신",
    ),
    sig(
        "llm_ollama",
        K::LocalLlm,
        42,
        A,
        ExeBase("ollama"),
        "Ollama 로컬 LLM",
    ),
    sig(
        "llm_mlx",
        K::LocalLlm,
        42,
        O,
        Any(&[
            Module("mlx_lm.server"),
            TokenSeq("mlx_lm", "server"),
            TokenBaseContains("mlx_lm.server"),
        ]),
        "MLX 로컬 LLM 서버",
    ),
    sig(
        "llm_llama_cpp",
        K::LocalLlm,
        42,
        O,
        ExeBaseAny(&["llama-server", "llama-cli"]),
        "llama.cpp 서버",
    ),
    sig(
        "llm_lmstudio",
        K::LocalLlm,
        42,
        A,
        Any(&[ExeContains("/LM Studio.app/"), ExeContains("/.lmstudio/")]),
        "LM Studio 로컬 LLM",
    ),
    sig(
        "db_postgres",
        K::Database,
        42,
        O,
        Any(&[ExeBase("postgres"), TitlePrefix("postgres:")]),
        "PostgreSQL",
    ),
    sig(
        "db_redis",
        K::Database,
        42,
        O,
        ExeBase("redis-server"),
        "Redis",
    ),
    sig(
        "db_mongod",
        K::Database,
        42,
        O,
        ExeBase("mongod"),
        "MongoDB",
    ),
    sig(
        "db_mysql",
        K::Database,
        42,
        O,
        ExeBaseAny(&["mysqld", "mariadbd"]),
        "MySQL",
    ),
    sig(
        "db_qdrant",
        K::Database,
        42,
        O,
        ExeBase("qdrant"),
        "Qdrant 벡터 DB",
    ),
    sig(
        "test_appium",
        K::TestTool,
        42,
        O,
        Any(&[
            NameBase("appium"),
            EntryContains("/appium/build/lib/main.js"),
        ]),
        "Appium 테스트 서버",
    ),
    sig(
        "test_playwright_runner",
        K::TestTool,
        42,
        O,
        Any(&[
            EntryContains("/@playwright/test/"),
            All(&[NameBase("playwright"), Token("test")]),
        ]),
        "Playwright 테스트 실행기",
    ),
    sig(
        "test_js_runner",
        K::TestTool,
        42,
        O,
        NameBaseAny(&["jest", "vitest"]),
        "테스트 실행기({entry_name})",
    ),
    sig(
        "test_agent_browser",
        K::TestTool,
        42,
        O,
        ExeBasePrefix("agent-browser"),
        "agent-browser 브라우저 자동화 데몬",
    ),
    sig(
        "android_adb_server",
        K::Emulator,
        42,
        O,
        All(&[ExeBase("adb"), Token("fork-server")]),
        "Android 디버그 브리지(adb) 서버",
    ),
    sig(
        "tun_ngrok",
        K::Tunnel,
        42,
        O,
        ExeBase("ngrok"),
        "ngrok 터널(외부 공개)",
    ),
    sig(
        "tun_cloudflared",
        K::Tunnel,
        42,
        O,
        All(&[ExeBase("cloudflared"), Token("tunnel")]),
        "Cloudflare 터널(외부 공개)",
    ),
    sig(
        "tun_localtunnel",
        K::Tunnel,
        42,
        O,
        NameBaseAny(&["lt", "localtunnel"]),
        "localtunnel(외부 공개)",
    ),
    sig(
        "tun_bore",
        K::Tunnel,
        42,
        O,
        All(&[ExeBase("bore"), Token("local")]),
        "bore 터널(외부 공개)",
    ),
    sig(
        "ls_tsserver",
        K::LanguageServer,
        50,
        O,
        TokenSuffixAny(&["/tsserver.js", "/typescript/lib/tsserver"]),
        "TypeScript 언어 서버(tsserver)",
    ),
    sig(
        "ls_ts_language_server",
        K::LanguageServer,
        50,
        O,
        NameBase("typescript-language-server"),
        "TypeScript 언어 서버",
    ),
    sig(
        "ls_pyright",
        K::LanguageServer,
        50,
        O,
        Any(&[
            NameBaseAny(&[
                "pyright",
                "pyright-langserver",
                "basedpyright",
                "basedpyright-langserver",
            ]),
            EntryContains("pyright/langserver.index.js"),
        ]),
        "Python 언어 서버(pyright)",
    ),
    sig(
        "ls_rust_analyzer",
        K::LanguageServer,
        50,
        O,
        ExeBase("rust-analyzer"),
        "Rust 언어 서버",
    ),
    sig(
        "ls_gopls",
        K::LanguageServer,
        50,
        O,
        ExeBase("gopls"),
        "Go 언어 서버",
    ),
    sig(
        "ls_eslint_d",
        K::LanguageServer,
        50,
        O,
        NameBase("eslint_d"),
        "eslint_d(린트 데몬)",
    ),
    sig(
        "ls_sourcekit",
        K::LanguageServer,
        50,
        A,
        ExeBase("sourcekit-lsp"),
        "Swift 언어 서버",
    ),
    sig(
        "ls_biome",
        K::LanguageServer,
        50,
        O,
        All(&[ExeBase("biome"), Token("__run_server")]),
        "Biome 린트·포맷 데몬",
    ),
    sig(
        "w_watchman",
        K::Watcher,
        50,
        O,
        ExeBase("watchman"),
        "watchman 파일 감시",
    ),
    sig(
        "w_esbuild_service",
        K::Watcher,
        50,
        O,
        All(&[ExeBase("esbuild"), TokenPrefixAny(&["--service"])]),
        "esbuild 서비스",
    ),
    sig(
        "w_turbo_daemon",
        K::Watcher,
        50,
        O,
        All(&[
            ExeBaseAny(&["turbo", "turbo-darwin-arm64"]),
            Token("daemon"),
        ]),
        "turbo 데몬",
    ),
    sig(
        "w_nx_daemon",
        K::Watcher,
        50,
        O,
        Any(&[EntryContains("/nx/src/daemon/"), TokenSeq("nx", "daemon")]),
        "nx 데몬",
    ),
    sig(
        "w_fswatch",
        K::Watcher,
        50,
        O,
        ExeBase("fswatch"),
        "fswatch 파일 감시",
    ),
    sig(
        "w_tsc_watch",
        K::Watcher,
        51,
        O,
        All(&[NameBase("tsc"), TokenAny(&["-w", "--watch"])]),
        "tsc 감시 컴파일",
    ),
    sig(
        "dev_next",
        K::DevServer,
        60,
        O,
        Any(&[
            All(&[NameBase("next"), Token("dev")]),
            TitlePrefix("next-server"),
        ]),
        "Next.js 개발 서버",
    ),
    sig(
        "dev_vite",
        K::DevServer,
        60,
        O,
        All(&[NameBase("vite"), NotTokenAny(&["build", "preview"])]),
        "Vite 개발 서버",
    ),
    sig(
        "dev_webpack_serve",
        K::DevServer,
        60,
        O,
        Any(&[
            All(&[NameBase("webpack"), Token("serve")]),
            NameBase("webpack-dev-server"),
        ]),
        "webpack 개발 서버",
    ),
    sig(
        "dev_nodemon",
        K::DevServer,
        60,
        O,
        NameBase("nodemon"),
        "nodemon(자동 재시작 서버)",
    ),
    sig(
        "dev_tsx_watch",
        K::DevServer,
        60,
        O,
        All(&[NameBase("tsx"), Token("watch")]),
        "tsx watch 개발 서버",
    ),
    sig(
        "dev_uvicorn",
        K::DevServer,
        60,
        O,
        Any(&[NameBase("uvicorn"), Module("uvicorn")]),
        "uvicorn(Python API 서버)",
    ),
    sig(
        "dev_gunicorn",
        K::DevServer,
        60,
        O,
        Any(&[NameBase("gunicorn"), Module("gunicorn")]),
        "gunicorn(Python 웹 서버)",
    ),
    sig(
        "dev_flask",
        K::DevServer,
        60,
        O,
        All(&[Any(&[NameBase("flask"), Module("flask")]), Token("run")]),
        "Flask 개발 서버",
    ),
    sig(
        "dev_streamlit",
        K::DevServer,
        60,
        O,
        All(&[
            Any(&[NameBase("streamlit"), Module("streamlit")]),
            Token("run"),
        ]),
        "Streamlit 앱",
    ),
    sig(
        "dev_gradio",
        K::DevServer,
        60,
        O,
        Any(&[NameBase("gradio"), Module("gradio")]),
        "Gradio 앱",
    ),
    sig(
        "dev_jupyter",
        K::DevServer,
        60,
        O,
        Any(&[
            NameBaseAny(&["jupyter-lab", "jupyter-notebook", "jupyter-server"]),
            TokenSeq("jupyter", "lab"),
            TokenSeq("jupyter", "notebook"),
        ]),
        "Jupyter 노트북 서버",
    ),
    sig(
        "dev_http_server",
        K::DevServer,
        60,
        O,
        Module("http.server"),
        "Python 간이 웹 서버",
    ),
    sig(
        "dev_rails",
        K::DevServer,
        60,
        O,
        Any(&[
            All(&[NameBase("rails"), TokenAny(&["s", "server"])]),
            NameBase("puma"),
        ]),
        "Rails 개발 서버",
    ),
    sig(
        "dev_bun_hot",
        K::DevServer,
        60,
        O,
        All(&[InterpIs(Interp::Bun), TokenAny(&["--hot", "--watch"])]),
        "bun 개발 서버(--hot)",
    ),
    sig(
        "dev_deno_task_dev",
        K::DevServer,
        60,
        O,
        All(&[InterpIs(Interp::Deno), TokenSeq("task", "dev")]),
        "deno 개발 서버",
    ),
    sig(
        "dev_expo_metro",
        K::DevServer,
        60,
        O,
        All(&[NameBaseAny(&["expo", "react-native"]), Token("start")]),
        "Expo/Metro 개발 서버",
    ),
    sig(
        "dev_ts_node",
        K::DevServer,
        61,
        O,
        NameBaseAny(&["ts-node", "ts-node-dev"]),
        "ts-node 실행",
    ),
    sig(
        "dev_jupyter_kernel",
        K::DevRuntime,
        61,
        O,
        Module("ipykernel_launcher"),
        "Jupyter 커널",
    ),
    sig(
        "dev_pkg_script",
        K::DevServer,
        62,
        O,
        All(&[
            NameBaseAny(&["npm", "npm-cli", "pnpm", "yarn"]),
            EnvIn("npm_lifecycle_event", &["dev", "start", "serve"]),
        ]),
        "npm 스크립트 실행기({npm_lifecycle_event})",
    ),
    sig(
        "dev_generic_dev",
        K::DevServer,
        63,
        O,
        All(&[InBinDir, SubAny(&["dev", "serve", "start"])]),
        "{entry_name} 개발 서버",
    ),
    sig(
        "build_gradle_daemon",
        K::BuildTool,
        70,
        O,
        TokenContains("org.gradle.launcher.daemon"),
        "Gradle 데몬",
    ),
    sig(
        "build_kotlin_daemon",
        K::BuildTool,
        70,
        O,
        TokenContains("KotlinCompileDaemon"),
        "Kotlin 컴파일 데몬",
    ),
    sig(
        "build_native",
        K::BuildTool,
        70,
        A,
        All(&[
            ExeBaseAny(&[
                "cargo",
                "rustc",
                "swift-build",
                "swift-frontend",
                "xcodebuild",
                "clang",
                "ld",
                "go",
            ]),
            NotExePrefix(&["/Applications/Xcode.app/Contents/MacOS/"]),
        ]),
        "빌드 도구({exe_base})",
    ),
    sig(
        "build_js",
        K::BuildTool,
        71,
        O,
        Any(&[
            All(&[
                NameBaseAny(&["vite", "next", "nuxt", "astro"]),
                Token("build"),
            ]),
            NameBaseAny(&["webpack", "esbuild", "rollup", "tsc", "turbo"]),
            All(&[
                NameBaseAny(&["npm", "npm-cli", "pnpm", "yarn", "bun"]),
                SubAny(&["install", "i", "ci", "add"]),
            ]),
        ]),
        "빌드 도구({entry_name})",
    ),
    sig(
        "app_xpc",
        K::AppHelper,
        80,
        A,
        All(&[InAppBundlePath, ExeContains(".xpc/")]),
        "{app}의 백그라운드 서비스(XPC)",
    ),
    sig(
        "app_appex",
        K::AppHelper,
        80,
        A,
        All(&[InAppBundlePath, ExeContains(".appex/")]),
        "{app}의 확장(appex)",
    ),
    sig(
        "gui_app_main",
        K::GuiApp,
        81,
        A,
        All(&[InAppBundlePath, BundleMain]),
        "{app} 앱",
    ),
    sig(
        "app_bundle_helper",
        K::AppHelper,
        82,
        A,
        InAppBundlePath,
        "{app} 도우미",
    ),
    sig(
        "app_privileged_helper",
        K::AppHelper,
        82,
        A,
        ExePrefix(&["/Library/PrivilegedHelperTools/"]),
        "{name} 권한 도우미",
    ),
    sig(
        "rt_interpreter",
        K::DevRuntime,
        90,
        A,
        Any(&[
            InterpIs(Interp::Node),
            InterpIs(Interp::Bun),
            InterpIs(Interp::Deno),
            InterpIs(Interp::Python),
            InterpIs(Interp::Ruby),
            InterpIs(Interp::Java),
            InterpIs(Interp::Uv),
            InterpIs(Interp::Php),
        ]),
        "{interp} 실행: {entry_name}",
    ),
    sig("other", K::Other, 99, A, Always, "{name}"),
];

const _: () = {
    let mut i = 1;
    while i < SIGNATURES.len() {
        assert!(SIGNATURES[i - 1].priority <= SIGNATURES[i].priority);
        i += 1;
    }
};

pub(crate) struct Ctx<'a> {
    pub p: &'a Proc,
    pub f: &'a Feat,
    pub home: &'a str,
}

fn home_rel(home: &str, rel: &str) -> String {
    format!("{}/{}", home.trim_end_matches('/'), rel)
}

fn is_agent_entry(c: &Ctx, which: &str) -> bool {
    let f = c.f;
    match which {
        "claude" => {
            f.exe_base == "claude"
                || f.exe_path
                    .starts_with(&home_rel(c.home, ".local/share/claude/versions/"))
                || f.name_base() == "claude"
                || f.entry
                    .as_deref()
                    .is_some_and(|e| e.contains("/claude-code/cli.js"))
        }
        "codex" => {
            f.exe_base == "codex"
                || f.name_base() == "codex"
                || f.entry
                    .as_deref()
                    .is_some_and(|e| e.contains("/@openai/codex/bin/codex"))
        }
        _ => false,
    }
}

pub(crate) fn eval(cond: &C, c: &Ctx) -> bool {
    let f = c.f;
    match cond {
        PidEq(pid) => c.p.pid == *pid,
        ExePrefix(ps) => ps.iter().any(|p| f.exe_path.starts_with(p)),
        NotExePrefix(ps) => !ps.iter().any(|p| f.exe_path.starts_with(p)),
        ExeContains(s) => f.exe_path.contains(s),
        ExeSuffix(s) => f.exe_path.ends_with(s),
        ExeBase(b) => f.exe_base == *b,
        ExeBaseAny(bs) => bs.contains(&f.exe_base.as_str()),
        ExeBasePrefix(b) => f.exe_base.starts_with(b),
        NameEq(n) => c.p.name == *n,
        TitlePrefix(t) => f.title.starts_with(t),
        InterpIs(i) => f.interp == Some(*i),
        EntryContains(s) => f.entry.as_deref().is_some_and(|e| e.contains(s)),
        EntrySuffix(s) => f.entry.as_deref().is_some_and(|e| e.ends_with(s)),
        NameBase(b) => f.name_base() == *b,
        NameBaseAny(bs) => bs.contains(&f.name_base()),
        Module(m) => f.module.as_deref() == Some(*m),
        SubAny(ss) => f.subcommand.as_deref().is_some_and(|s| ss.contains(&s)),
        Token(t) => f.tokens.iter().skip(1).any(|x| x == t),
        TokenAny(ts) => f.tokens.iter().skip(1).any(|x| ts.contains(&x.as_str())),
        TokenSeq(a, b) => f
            .tokens
            .windows(2)
            .any(|w| token_base(&w[0]) == *a && w[1] == *b),
        TokenContains(s) => f.tokens.iter().any(|x| x.contains(s)),
        TokenPrefixAny(ps) => f
            .tokens
            .iter()
            .skip(1)
            .any(|x| ps.iter().any(|p| x.starts_with(p))),
        TokenSuffixAny(ss) => f.tokens.iter().any(|x| ss.iter().any(|s| x.ends_with(s))),
        TokenBaseContains(s) => f.tokens.iter().any(|x| token_base(x).contains(s)),
        TokenBasePrefix(p) => f.tokens.iter().any(|x| token_base(x).starts_with(p)),
        TokenBaseSuffixAny(ss) => f
            .tokens
            .iter()
            .any(|x| ss.iter().any(|s| token_base(x).ends_with(s))),
        NotTokenAny(ts) => !f.tokens.iter().skip(1).any(|x| ts.contains(&x.as_str())),
        ChromiumExe => CHROMIUM_BASES.contains(&f.exe_base.as_str()),
        InBinDir => f
            .entry
            .as_deref()
            .is_some_and(|e| e.contains("/node_modules/.bin/")),
        EnvIn(k, vs) => c.p.env.get(*k).is_some_and(|v| vs.contains(&v.as_str())),
        EnvHas(k) => c.p.env.contains_key(*k),
        BundleMain => f.bundle_main,
        InAppBundlePath => f.app_count > 0 && f.origin != ExeOrigin::DevToolBundle,
        AgentEntry(w) => is_agent_entry(c, w),
        All(cs) => cs.iter().all(|x| eval(x, c)),
        Any(cs) => cs.iter().any(|x| eval(x, c)),
        Always => true,
    }
}

fn mcp_name(f: &Feat) -> String {
    let tok = f.tokens.iter().find_map(|t| {
        let b = token_base(t);
        if let Some(i) = t.find("@modelcontextprotocol/server-") {
            let rest = &t[i + "@modelcontextprotocol/server-".len()..];
            return Some(rest.split(['/', '@']).next().unwrap_or(rest).to_string());
        }
        if let Some(i) = b.find("[mcp]") {
            return Some(b[..i].to_string());
        }
        if let Some(rest) = b.strip_prefix("mcp-server-") {
            return Some(rest.to_string());
        }
        ["-mcp", "_mcp"]
            .iter()
            .find_map(|s| b.strip_suffix(s))
            .map(str::to_string)
    });
    tok.unwrap_or_else(|| f.name_base().to_string())
}

fn render(label: &str, c: &Ctx) -> String {
    if !label.contains('{') {
        return label.to_string();
    }
    let f = c.f;
    let name = if c.p.name.is_empty() {
        safe(&f.exe_base)
    } else {
        c.p.name.clone()
    };
    let mut out = label.to_string();
    let subs: [(&str, &dyn Fn() -> String); 7] = [
        ("{app}", &|| f.app.clone().unwrap_or_else(|| name.clone())),
        ("{name}", &|| name.clone()),
        ("{entry_name}", &|| safe(f.name_base())),
        ("{exe_base}", &|| safe(&f.exe_base)),
        ("{interp}", &|| {
            f.interp.map(|i| i.name()).unwrap_or("").to_string()
        }),
        ("{mcp_name}", &|| safe(&mcp_name(f))),
        ("{npm_lifecycle_event}", &|| {
            c.p.env
                .get("npm_lifecycle_event")
                .cloned()
                .unwrap_or_default()
        }),
    ];
    for (key, val) in subs {
        if out.contains(key) {
            out = out.replace(key, &val());
        }
    }
    out
}

#[derive(Debug, Clone)]
pub(crate) struct Class {
    pub kind: Kind,
    pub sig: &'static str,
    pub label: String,
}

pub(crate) fn classify(p: &Proc, f: &Feat, home: &str) -> Class {
    let c = Ctx { p, f, home };
    let in_bundle = f.origin == ExeOrigin::AppBundle;
    for s in SIGNATURES {
        if in_bundle && s.scope == Scope::OutsideBundle {
            continue;
        }
        if eval(&s.cond, &c) {
            return Class {
                kind: s.kind,
                sig: s.id,
                label: render(s.label, &c),
            };
        }
    }
    Class {
        kind: Kind::Other,
        sig: "other",
        label: render("{name}", &c),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use vh_model::{Kind, Proc, ProcStatus};

    use super::{SIGNATURES, classify};
    use crate::features::features;

    const H: &str = "/Users/demo/";
    const NODE: &str = "/Users/demo/.local/share/fnm/node-versions/v24.0.0/installation/bin/node";
    const HBPY: &str = "/opt/homebrew/Cellar/python@3.13/3.13.1/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python";
    const XPY: &str = "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python";
    const CL: &str = "/Users/demo/.local/share/claude/versions/2.1.0";
    const CFT: &str =
        "/Users/demo/.agent-browser/browsers/chrome-140/Google Chrome for Testing.app";

    struct Ex {
        pid: i32,
        exe: String,
        argv: Vec<String>,
        name: String,
        env: BTreeMap<String, String>,
    }

    fn ex(exe: &str, argv: &[&str]) -> Ex {
        Ex {
            pid: 4242,
            exe: exe.to_string(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            name: exe.rsplit('/').next().unwrap_or(exe).to_string(),
            env: BTreeMap::new(),
        }
    }

    fn run(e: &Ex) -> (Kind, &'static str, String) {
        let p = Proc {
            pid: e.pid,
            ppid: 1,
            pgid: e.pid,
            uid: 501,
            start_time_unix_ms: 0,
            name: e.name.clone(),
            exe: Some(e.exe.clone()),
            argv: e.argv.clone(),
            argv_readable: true,
            env: e.env.clone(),
            env_readable: true,
            cwd: None,
            status: ProcStatus::Sleeping,
            has_tty: false,
            footprint_bytes: None,
            rss_bytes: None,
            cpu_time_ns: None,
            cpu_pct: None,
            threads: None,
            nice: None,
            translated: false,
            tcp: None,
            disk_read_bytes: None,
            disk_written_bytes: None,
            disk_io_delta_bytes: None,
        };
        let f = features(&p);
        let c = classify(&p, &f, H);
        (c.kind, c.sig, c.label)
    }

    fn examples() -> Vec<(&'static str, Ex)> {
        let bin = |name: &str| format!("{H}dev/shop/node_modules/.bin/{name}");
        let mut v: Vec<(&'static str, Ex)> = vec![
            (
                "sys_controlcenter",
                ex(
                    "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter",
                    &["ControlCenter"],
                ),
            ),
            (
                "sys_system",
                ex(
                    "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
                    &["Finder"],
                ),
            ),
            ("sys_libexec", ex("/usr/libexec/trustd", &["trustd"])),
            ("sys_sbin", ex("/usr/sbin/cfprefsd", &["cfprefsd", "agent"])),
            (
                "sys_library_apple",
                ex("/Library/Apple/System/Library/Demo/demod", &["demod"]),
            ),
            (
                "emu_sim_runtime",
                ex(
                    "/Library/Developer/CoreSimulator/Volumes/iOS/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS.simruntime/Contents/Resources/RuntimeRoot/usr/libexec/trustd",
                    &["trustd"],
                ),
            ),
            (
                "sys_developer_private",
                ex(
                    "/Library/Developer/PrivateFrameworks/CoreSimulator.framework/Versions/A/Resources/bin/simdemo",
                    &["simdemo"],
                ),
            ),
            (
                "agent_codex_app_server",
                ex(
                    NODE,
                    &[
                        "node",
                        "/Users/demo/.local/state/fnm_multishells/1_2/bin/codex",
                        "app-server",
                    ],
                ),
            ),
            (
                "agent_codex_code_mode_host",
                ex(
                    "/Users/demo/x/vendor/aarch64-apple-darwin/bin/codex-code-mode-host",
                    &["codex-code-mode-host"],
                ),
            ),
            (
                "agent_claude_bg",
                ex(
                    CL,
                    &["claude bg-spare --bg-spare /tmp/cc-daemon-501/a/spare/b.claim.sock"],
                ),
            ),
            (
                "agent_claude_daemon",
                ex(CL, &["/Users/demo/.local/bin/claude", "daemon", "run"]),
            ),
            (
                "mcp_chrome_devtools",
                ex(NODE, &["npm exec chrome-devtools-mcp@1.9.0"]),
            ),
            (
                "mcp_xcodebuild",
                ex(
                    NODE,
                    &[
                        "node",
                        "/Users/demo/.npm/_npx/a1/node_modules/.bin/xcodebuildmcp",
                        "mcp",
                    ],
                ),
            ),
            (
                "mcp_convex",
                ex(
                    NODE,
                    &[
                        "node",
                        "/Users/demo/.npm/_npx/b2/node_modules/.bin/convex",
                        "mcp",
                        "start",
                    ],
                ),
            ),
            (
                "mcp_modelcontextprotocol",
                ex(
                    NODE,
                    &[
                        "node",
                        "/Users/demo/.npm/_npx/c3/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
                        "/Users/demo/dev",
                    ],
                ),
            ),
            (
                "mcp_server_prefix",
                ex("/Users/demo/.local/bin/uvx", &["uvx", "mcp-server-fetch"]),
            ),
            (
                "mcp_name_suffix",
                ex(
                    NODE,
                    &[
                        "node",
                        "/Users/demo/.npm/_npx/d4/node_modules/.bin/figma-mcp",
                    ],
                ),
            ),
            (
                "mcp_subcommand",
                ex("/Users/demo/.local/bin/aside", &["aside", "mcp"]),
            ),
            (
                "agent_claude_native",
                ex(
                    CL,
                    &[
                        "claude",
                        "--session-id",
                        "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                    ],
                ),
            ),
            (
                "agent_omo",
                ex(
                    "/Users/demo/.bun/bin/bun",
                    &[
                        "bun",
                        "/Users/demo/.bun/install/global/node_modules/@demo/senpi/dist/bundle/cli.js",
                    ],
                ),
            ),
            (
                "agent_codex",
                ex(
                    "/Users/demo/x/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex",
                    &["codex"],
                ),
            ),
            (
                "hb_chrome_for_testing",
                ex(
                    &format!("{CFT}/Contents/MacOS/Google Chrome for Testing"),
                    &["Google Chrome for Testing"],
                ),
            ),
            (
                "hb_headless_shell",
                ex(
                    "/Users/demo/.cache/x/chrome-headless-shell",
                    &["chrome-headless-shell"],
                ),
            ),
            (
                "hb_playwright",
                ex(
                    "/Users/demo/Library/Caches/ms-playwright/chromium-1100/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
                    &["Chromium"],
                ),
            ),
            (
                "hb_puppeteer",
                ex(
                    "/Users/demo/.cache/puppeteer/chrome-headless/x/chrome",
                    &["chrome"],
                ),
            ),
            (
                "hb_flag_headless",
                ex(
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    &["Google Chrome", "--headless=new"],
                ),
            ),
            (
                "hb_flag_remote_debug",
                ex(
                    "/opt/homebrew/bin/chromium",
                    &["chromium", "--remote-debugging-port=9222"],
                ),
            ),
            (
                "emu_qemu_android",
                ex(
                    "/Users/demo/Library/Android/sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64",
                    &["qemu-system-aarch64", "-avd", "pixel"],
                ),
            ),
            (
                "emu_android_emulator",
                ex(
                    "/Users/demo/Library/Android/sdk/emulator/emulator",
                    &["emulator", "-avd", "pixel"],
                ),
            ),
            (
                "emu_android_aux",
                ex(
                    "/Users/demo/Library/Android/sdk/emulator/netsimd",
                    &["netsimd"],
                ),
            ),
            (
                "emu_ios_simulator_app",
                ex(
                    "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app/Contents/MacOS/Simulator",
                    &["Simulator"],
                ),
            ),
            (
                "vm_orbstack",
                ex(
                    "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper",
                    &["OrbStack Helper", "vmgr"],
                ),
            ),
            (
                "vm_docker",
                ex(
                    "/Applications/Docker.app/Contents/MacOS/com.docker.backend",
                    &["com.docker.backend"],
                ),
            ),
            (
                "vm_lima",
                ex("/opt/homebrew/bin/limactl", &["limactl", "hostagent"]),
            ),
            (
                "vm_qemu_generic",
                ex(
                    "/opt/homebrew/bin/qemu-system-aarch64",
                    &["qemu-system-aarch64", "-machine", "virt"],
                ),
            ),
            (
                "llm_ollama",
                ex("/opt/homebrew/bin/ollama", &["ollama", "serve"]),
            ),
            (
                "llm_mlx",
                ex(HBPY, &["python3", "-m", "mlx_lm.server", "--model", "demo"]),
            ),
            (
                "llm_llama_cpp",
                ex(
                    "/opt/homebrew/bin/llama-server",
                    &["llama-server", "-m", "demo.gguf"],
                ),
            ),
            (
                "llm_lmstudio",
                ex("/Users/demo/.lmstudio/bin/lms", &["lms", "server", "start"]),
            ),
            (
                "db_postgres",
                ex(
                    "/opt/homebrew/opt/postgresql@17/bin/postgres",
                    &["postgres", "-D", "/opt/homebrew/var/postgresql@17"],
                ),
            ),
            (
                "db_redis",
                ex(
                    "/opt/homebrew/bin/redis-server",
                    &["redis-server", "*:6379"],
                ),
            ),
            ("db_mongod", ex("/opt/homebrew/bin/mongod", &["mongod"])),
            ("db_mysql", ex("/opt/homebrew/bin/mysqld", &["mysqld"])),
            ("db_qdrant", ex("/opt/homebrew/bin/qdrant", &["qdrant"])),
            (
                "test_appium",
                ex(
                    NODE,
                    &[
                        "node",
                        "/Users/demo/.npm/_npx/0a/node_modules/.bin/appium",
                        "--port",
                        "4723",
                    ],
                ),
            ),
            (
                "test_playwright_runner",
                ex(
                    NODE,
                    &[
                        "node",
                        "/Users/demo/dev/shop/node_modules/@playwright/test/cli.js",
                        "test",
                    ],
                ),
            ),
            ("test_js_runner", ex(NODE, &["node", &bin("vitest")])),
            (
                "tun_ngrok",
                ex("/opt/homebrew/bin/ngrok", &["ngrok", "http", "3000"]),
            ),
            (
                "tun_cloudflared",
                ex(
                    "/opt/homebrew/bin/cloudflared",
                    &["cloudflared", "tunnel", "run"],
                ),
            ),
            (
                "tun_localtunnel",
                ex(NODE, &["node", &bin("lt"), "--port", "3000"]),
            ),
            (
                "tun_bore",
                ex(
                    "/opt/homebrew/bin/bore",
                    &["bore", "local", "3000", "--to", "bore.pub"],
                ),
            ),
            (
                "ls_tsserver",
                ex(
                    NODE,
                    &[
                        "node",
                        "/Users/demo/dev/shop/node_modules/typescript/lib/tsserver.js",
                        "--useNodeIpc",
                    ],
                ),
            ),
            (
                "ls_ts_language_server",
                ex(
                    NODE,
                    &["node", &bin("typescript-language-server"), "--stdio"],
                ),
            ),
            (
                "ls_pyright",
                ex(NODE, &["node", &bin("pyright-langserver"), "--stdio"]),
            ),
            (
                "ls_rust_analyzer",
                ex("/opt/homebrew/bin/rust-analyzer", &["rust-analyzer"]),
            ),
            (
                "ls_gopls",
                ex("/Users/demo/go/bin/gopls", &["gopls", "serve"]),
            ),
            ("ls_eslint_d", ex(NODE, &["node", &bin("eslint_d")])),
            (
                "ls_sourcekit",
                ex(
                    "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/sourcekit-lsp",
                    &["sourcekit-lsp"],
                ),
            ),
            (
                "w_watchman",
                ex("/opt/homebrew/bin/watchman", &["watchman", "--foreground"]),
            ),
            (
                "w_esbuild_service",
                ex(
                    "/Users/demo/dev/shop/node_modules/@esbuild/darwin-arm64/bin/esbuild",
                    &["esbuild", "--service=0.20.0", "--ping"],
                ),
            ),
            (
                "w_turbo_daemon",
                ex(
                    "/Users/demo/dev/shop/node_modules/turbo-darwin-arm64/bin/turbo",
                    &["turbo", "daemon"],
                ),
            ),
            (
                "w_nx_daemon",
                ex(
                    NODE,
                    &[
                        "node",
                        "/Users/demo/dev/shop/node_modules/nx/src/daemon/server/start.js",
                    ],
                ),
            ),
            (
                "w_fswatch",
                ex("/opt/homebrew/bin/fswatch", &["fswatch", "."]),
            ),
            ("w_tsc_watch", ex(NODE, &["node", &bin("tsc"), "--watch"])),
            ("dev_next", ex(NODE, &["node", &bin("next"), "dev"])),
            ("dev_vite", ex(NODE, &["node", &bin("vite")])),
            (
                "dev_webpack_serve",
                ex(NODE, &["node", &bin("webpack"), "serve"]),
            ),
            (
                "dev_nodemon",
                ex(NODE, &["node", &bin("nodemon"), "server.js"]),
            ),
            (
                "dev_tsx_watch",
                ex(NODE, &["node", &bin("tsx"), "watch", "src/index.ts"]),
            ),
            (
                "dev_uvicorn",
                ex(
                    HBPY,
                    &[
                        HBPY,
                        "/Users/demo/dev/shop/api/.venv/bin/uvicorn",
                        "app:app",
                    ],
                ),
            ),
            (
                "dev_gunicorn",
                ex(HBPY, &["python3", "-m", "gunicorn", "app:app"]),
            ),
            ("dev_flask", ex(HBPY, &["python3", "-m", "flask", "run"])),
            (
                "dev_streamlit",
                ex(
                    HBPY,
                    &[
                        "python3",
                        "/Users/demo/dev/shop/.venv/bin/streamlit",
                        "run",
                        "app.py",
                    ],
                ),
            ),
            (
                "dev_gradio",
                ex(
                    HBPY,
                    &["python3", "/Users/demo/dev/shop/.venv/bin/gradio", "app.py"],
                ),
            ),
            (
                "dev_jupyter",
                ex(
                    HBPY,
                    &["python3", "/Users/demo/dev/shop/.venv/bin/jupyter-lab"],
                ),
            ),
            (
                "dev_http_server",
                ex(XPY, &[XPY, "-m", "http.server", "8000"]),
            ),
            (
                "dev_rails",
                ex(
                    "/opt/homebrew/opt/ruby/bin/ruby",
                    &["ruby", "bin/rails", "server"],
                ),
            ),
            (
                "dev_bun_hot",
                ex("/Users/demo/.bun/bin/bun", &["bun", "--hot", "server.ts"]),
            ),
            (
                "dev_deno_task_dev",
                ex("/opt/homebrew/bin/deno", &["deno", "task", "dev"]),
            ),
            ("dev_expo_metro", ex(NODE, &["node", &bin("expo"), "start"])),
            (
                "dev_ts_node",
                ex(NODE, &["node", &bin("ts-node"), "src/index.ts"]),
            ),
            (
                "dev_jupyter_kernel",
                ex(
                    HBPY,
                    &["python3", "-m", "ipykernel_launcher", "-f", "k.json"],
                ),
            ),
            ("dev_generic_dev", ex(NODE, &["node", &bin("astro"), "dev"])),
            (
                "build_gradle_daemon",
                ex(
                    "/opt/homebrew/opt/openjdk/bin/java",
                    &[
                        "java",
                        "-cp",
                        "gradle.jar",
                        "org.gradle.launcher.daemon.bootstrap.GradleDaemon",
                        "8.5",
                    ],
                ),
            ),
            (
                "build_kotlin_daemon",
                ex(
                    "/opt/homebrew/opt/openjdk/bin/java",
                    &[
                        "java",
                        "-cp",
                        "k.jar",
                        "org.jetbrains.kotlin.daemon.KotlinCompileDaemon",
                    ],
                ),
            ),
            (
                "build_native",
                ex("/Users/demo/.cargo/bin/cargo", &["cargo", "build"]),
            ),
            ("build_js", ex(NODE, &["node", &bin("vite"), "build"])),
            (
                "app_xpc",
                ex(
                    "/Applications/Demo.app/Contents/XPCServices/H.xpc/Contents/MacOS/H",
                    &["H"],
                ),
            ),
            (
                "app_appex",
                ex(
                    "/Applications/Demo.app/Contents/PlugIns/W.appex/Contents/MacOS/W",
                    &["W"],
                ),
            ),
            (
                "gui_app_main",
                ex("/Applications/Demo.app/Contents/MacOS/Demo", &["Demo"]),
            ),
            (
                "app_bundle_helper",
                ex(
                    "/Applications/Demo.app/Contents/Frameworks/Demo Helper.app/Contents/MacOS/Demo Helper",
                    &["Demo Helper"],
                ),
            ),
            (
                "app_privileged_helper",
                ex(
                    "/Library/PrivilegedHelperTools/com.demo.helper",
                    &["com.demo.helper"],
                ),
            ),
            ("rt_interpreter", ex(NODE, &["node", "server.js"])),
            ("other", ex("/opt/homebrew/bin/htop", &["htop"])),
        ];
        v.extend([
            (
                "agent_codex_broker",
                ex(NODE, &["node", "/Users/demo/.claude/plugins/cache/openai-codex/codex/1.0.3/scripts/app-server-broker.mjs", "serve"]),
            ),
            (
                "agent_omo_py_kernel",
                ex(XPY, &[XPY, "-u", "/Users/demo/.omo/agent/runtime/r1/node_modules/@demo/senpi-codemode/src/kernels/py/prelude.py"]),
            ),
            (
                "agent_omo_lsp_daemon",
                ex("/Users/demo/.bun/bin/bun", &["bun", "/Users/demo/.bun/install/global/node_modules/omo-ai/plugin/runtime/lsp-daemon/dist/cli.js", "daemon"]),
            ),
            (
                "mcp_extra_spec",
                ex("/Users/demo/.local/bin/uv", &["uv", "tool", "uvx", "--isolated", "--from", "ouroboros-ai[mcp]"]),
            ),
            (
                "test_agent_browser",
                ex("/Users/demo/.local/lib/node_modules/agent-browser/bin/agent-browser-darwin-arm64", &["agent-browser-darwin-arm64"]),
            ),
            (
                "android_adb_server",
                ex("/Users/demo/Library/Android/sdk/platform-tools/adb", &["adb", "-L", "tcp:5037", "fork-server", "server"]),
            ),
            (
                "ls_biome",
                ex("/Users/demo/dev/shop/node_modules/@biomejs/cli-darwin-arm64/biome", &["biome", "__run_server", "--stop-on-disconnect"]),
            ),
        ]);
        let mut launchd = ex("/sbin/launchd", &["/sbin/launchd"]);
        launchd.pid = 1;
        v.push(("sys_launchd", launchd));
        let mut pkg = ex(
            NODE,
            &[
                "node",
                "/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js",
                "run",
                "dev",
            ],
        );
        pkg.env.insert("npm_lifecycle_event".into(), "dev".into());
        v.push(("dev_pkg_script", pkg));
        v
    }

    #[test]
    fn table_invariants() {
        let ids: BTreeSet<&str> = SIGNATURES.iter().map(|s| s.id).collect();
        assert_eq!(ids.len(), SIGNATURES.len(), "id 중복");
        assert!(SIGNATURES.iter().all(|s| !s.label.is_empty()));
        let all = [
            Kind::System,
            Kind::AppHelper,
            Kind::GuiApp,
            Kind::AgentCli,
            Kind::AgentHelper,
            Kind::McpServer,
            Kind::DevServer,
            Kind::LanguageServer,
            Kind::Watcher,
            Kind::BuildTool,
            Kind::HeadlessBrowser,
            Kind::Emulator,
            Kind::VirtualMachine,
            Kind::LocalLlm,
            Kind::Database,
            Kind::TestTool,
            Kind::Tunnel,
            Kind::DevRuntime,
            Kind::Other,
        ];
        for k in all {
            assert!(SIGNATURES.iter().any(|s| s.kind == k), "{k:?} 행 없음");
        }
    }

    #[test]
    fn every_row_has_a_positive_example() {
        let mut hit = BTreeSet::new();
        for (want, e) in examples() {
            let (_, got, label) = run(&e);
            assert_eq!(got, want, "{} {:?} → {got} ({label})", e.exe, e.argv);
            assert!(!label.contains('{'), "템플릿이 남음: {label}");
            hit.insert(got);
        }
        let missing: Vec<&str> = SIGNATURES
            .iter()
            .map(|s| s.id)
            .filter(|id| !hit.contains(id))
            .collect();
        assert!(missing.is_empty(), "예가 없는 행: {missing:?}");
    }

    #[test]
    fn labels_fill_names() {
        assert_eq!(run(&ex(NODE, &["node", "/Users/demo/.npm/_npx/c3/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"])).2, "MCP 서버: filesystem");
        assert_eq!(
            run(&ex(
                "/Users/demo/.local/bin/uvx",
                &["uvx", "mcp-server-fetch"]
            ))
            .2,
            "MCP 서버: fetch"
        );
        assert_eq!(
            run(&ex("/Users/demo/.local/bin/aside", &["aside", "mcp"])).2,
            "MCP 서버: aside"
        );
        assert_eq!(
            run(&ex(
                "/Users/demo/.local/bin/uv",
                &["uv", "tool", "uvx", "--from", "ouroboros-ai[mcp]"]
            ))
            .2,
            "MCP 서버: ouroboros-ai"
        );
        assert_eq!(
            run(&ex("/Applications/Demo.app/Contents/MacOS/Demo", &["Demo"])).2,
            "Demo 앱"
        );
    }

    #[test]
    fn known_false_positives_stay_out() {
        let k = |exe: &str, argv: &[&str]| run(&ex(exe, argv));
        assert_eq!(k(HBPY, &["python3", "-c", "print(1)"]).0, Kind::DevRuntime);
        assert_eq!(
            k(
                XPY,
                &[XPY, "-u", "/Users/demo/.omo/agent/runtime/kernel.py"]
            )
            .0,
            Kind::DevRuntime
        );
        let helper = format!(
            "{CFT}/Contents/Frameworks/Google Chrome for Testing Framework.framework/Versions/140/Helpers/Google Chrome for Testing Helper.app/Contents/MacOS/Google Chrome for Testing Helper"
        );
        assert_eq!(
            k(
                &helper,
                &["Google Chrome for Testing Helper", "--type=renderer"]
            )
            .0,
            Kind::HeadlessBrowser
        );
        let cmux = "/Applications/cmux.app/Contents/Resources/bin/cmux";
        assert_eq!(
            k(cmux, &[cmux, "hooks", "claude", "spool-forwarder"]).0,
            Kind::AppHelper
        );
        let cua = "/Applications/cmux.app/Contents/Resources/bin/cmux-cua";
        assert_eq!(
            k(cua, &[cua, "mcp", "--socket", "/tmp/x.sock"]).0,
            Kind::McpServer
        );
        assert_eq!(
            k(
                NODE,
                &[
                    "node",
                    "/Users/demo/dev/mcp-dashboard/node_modules/.bin/next",
                    "dev"
                ]
            )
            .1,
            "dev_next"
        );
        assert_eq!(
            k(
                "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node",
                &["node", "repl.js"]
            )
            .0,
            Kind::AppHelper
        );
        assert_eq!(
            k(
                "/Library/Developer/CoreSimulator/Volumes/iOS/RuntimeRoot/usr/libexec/logd",
                &["logd"]
            )
            .0,
            Kind::Emulator
        );
        assert_eq!(
            k(
                NODE,
                &[
                    "node",
                    "/Users/demo/dev/shop/node_modules/.bin/vite",
                    "build"
                ]
            )
            .0,
            Kind::BuildTool
        );
    }
}
