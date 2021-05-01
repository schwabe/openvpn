include(vcpkg_common_functions)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO OpenVPN/ovpn-dco-win
    REF 46ed95e0a5f0e34060c78acf499356c3b5110993
    SHA512 62bcf84d609abc07d6ce26ecdfed4d40c46e937f6ee417f348ecf4115f3283b819b6a477c951b80ed879a89cf9afa7c4c279b343fb54aa626fc4983b3176d42d
    HEAD_REF master
)

file(COPY ${SOURCE_PATH}/uapi/ovpn-dco.h DESTINATION ${CURRENT_PACKAGES_DIR}/include/ovpn-dco-win/uapi/)


file(INSTALL
    ${SOURCE_PATH}/COPYRIGHT.MIT
    DESTINATION ${CURRENT_PACKAGES_DIR}/share/ovpn-dco-win RENAME copyright)
