## [Unreleased]
### Added
- Token exchange method
- Flag to disable library automatically setting access token, allowing client app more fine-grained control
- idp_hint, login_hint support in authorize
- Dynamic redirect URI support

### Fixed
- Silent authentication doesn't give up after first fail
- The "Unicode Problem" with 16-bit-encoded strings

## [1.0.0] - 2020-12-02
### Changed
- Refactor to use Cloudentity ACP and PKCE as default authorization method

## [0.10.0] - 2019-04-12
### Added
- initial client (basic OAuth implicit flow support) - WIP
- basic options validation
- basic documentation - WIP
- build config
- configurable 'authorizationUri' and 'userInfoUri' when this urls needs to by customized, 'domain' options has some predefined values provided e.g. protocol, pathnames
- nonce support

## [Project init]
### Added
- initial project files
- EULA
