import os
import subprocess

Import("env")

def get_firmware_specifier_build_flag():
    ret = subprocess.run(["git", "describe"], stdout=subprocess.PIPE, text=True) #Uses only annotated tags
    #ret = subprocess.run(["git", "describe", "--tags"], stdout=subprocess.PIPE, text=True) #Uses any tags
    build_version = ret.stdout.strip()
    # fix unwanted and verbose tags
    build_version = build_version.replace('Release', '')
    build_flag = "-D AUTO_VERSION=\\\"" + build_version + "\\\""
    print ("Firmware Revision: " + build_version)
    return (build_flag)

env.Append(
    BUILD_FLAGS=[get_firmware_specifier_build_flag()]
)

_proj = env.subst("$PROJECT_DIR").replace("\\", "/")
_home = os.path.expanduser("~").replace("\\", "/")
_prefix_flags = [
    f"-ffile-prefix-map={_proj}=.",
    f"-ffile-prefix-map={_home}=.",
    f"-fmacro-prefix-map={_proj}=.",
    f"-fmacro-prefix-map={_home}=.",
]
env.Append(CCFLAGS=_prefix_flags, CXXFLAGS=_prefix_flags, ASFLAGS=_prefix_flags)
