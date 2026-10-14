use stopcat_model::{ExeOrigin, exe_origin};

#[test]
fn none_is_unknown() {
    assert_eq!(exe_origin(None), ExeOrigin::Unknown);
}

#[test]
fn empty_is_unknown() {
    assert_eq!(exe_origin(Some("")), ExeOrigin::Unknown);
}

#[test]
fn system_control_center() {
    assert_eq!(
        exe_origin(Some(
            "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"
        )),
        ExeOrigin::System
    );
}

#[test]
fn system_xpc_service() {
    assert_eq!(
        exe_origin(Some(
            "/System/Library/PrivateFrameworks/Demo.framework/XPCServices/Demo.xpc/Contents/MacOS/Demo"
        )),
        ExeOrigin::System
    );
}

#[test]
fn usr_libexec_and_sbin() {
    assert_eq!(exe_origin(Some("/usr/libexec/xpcproxy")), ExeOrigin::System);
}

#[test]
fn library_apple() {
    assert_eq!(
        exe_origin(Some("/Library/Apple/System/Library/Demo")),
        ExeOrigin::System
    );
}

#[test]
fn orbstack_helper() {
    assert_eq!(
        exe_origin(Some(
            "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper"
        )),
        ExeOrigin::AppBundle
    );
}

#[test]
fn app_xpc_inside_app() {
    assert_eq!(
        exe_origin(Some(
            "/Applications/Demo.app/Contents/XPCServices/Agent.xpc/Contents/MacOS/Agent"
        )),
        ExeOrigin::AppBundle
    );
}

#[test]
fn appex_anywhere() {
    assert_eq!(
        exe_origin(Some("/Users/demo/dev/Thing.appex/Contents/MacOS/Thing")),
        ExeOrigin::AppBundle
    );
}

#[test]
fn adobe_library_app() {
    assert_eq!(
        exe_origin(Some(
            "/Library/Application Support/Adobe/Adobe Desktop Common/ADS/Adobe Desktop Service.app/Contents/MacOS/Adobe Desktop Service"
        )),
        ExeOrigin::AppBundle
    );
}

#[test]
fn user_applications_app() {
    assert_eq!(
        exe_origin(Some(
            "/Users/demo/Applications/Demo.app/Contents/MacOS/Demo"
        )),
        ExeOrigin::AppBundle
    );
}

#[test]
fn xcode_python3() {
    assert_eq!(
        exe_origin(Some(
            "/Applications/Xcode.app/Contents/Developer/usr/bin/python3"
        )),
        ExeOrigin::DevToolBundle
    );
}

#[test]
fn homebrew_python() {
    assert_eq!(
        exe_origin(Some(
            "/opt/homebrew/Cellar/python@3.13/3.13.1/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python"
        )),
        ExeOrigin::DevToolBundle
    );
}

#[test]
fn python_org_python() {
    assert_eq!(
        exe_origin(Some(
            "/Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python"
        )),
        ExeOrigin::DevToolBundle
    );
}

#[test]
fn python_app_inside_app() {
    assert_eq!(
        exe_origin(Some(
            "/Applications/Blender.app/Contents/Resources/python/Python.app/Contents/MacOS/Python"
        )),
        ExeOrigin::AppBundle
    );
}

#[test]
fn chrome_for_testing_cache() {
    assert_eq!(
        exe_origin(Some(
            "/Users/demo/Library/Caches/ms-playwright/chromium-1140/chrome-mac/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
        )),
        ExeOrigin::User
    );
}

#[test]
fn claude_versions() {
    assert_eq!(
        exe_origin(Some("/Users/demo/.local/share/claude/versions/2.1.0")),
        ExeOrigin::User
    );
}

#[test]
fn homebrew_and_bun() {
    assert_eq!(exe_origin(Some("/opt/homebrew/bin/node")), ExeOrigin::User);
}

#[test]
fn bun_home() {
    assert_eq!(
        exe_origin(Some("/Users/demo/.bun/bin/bun")),
        ExeOrigin::User
    );
}

#[test]
fn app_outside_allowed_prefix() {
    assert_eq!(
        exe_origin(Some("/Users/demo/dev/MyApp.app/Contents/MacOS/MyApp")),
        ExeOrigin::User
    );
}

#[test]
fn platform_usr_bin() {
    assert_eq!(exe_origin(Some("/usr/bin/python3")), ExeOrigin::Platform);
}

#[test]
fn platform_bin() {
    assert_eq!(exe_origin(Some("/bin/zsh")), ExeOrigin::Platform);
}
