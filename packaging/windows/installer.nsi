; TimENC installer for Windows.
;
; Build: makensis /DVERSION=3.3.0 /DEXE=path\to\timenc-gui.exe /DOUTFILE=TimENC_3.3.0_x64-setup.exe installer.nsi
;
; Installs for the current user only (no administrator prompt), into the same
; folder and under the same uninstall entry as the earlier Tauri-built
; installer, so it upgrades an existing installation in place.

Unicode true
!include "MUI2.nsh"

!ifndef VERSION
  !error "Pass /DVERSION=x.y.z"
!endif
!ifndef EXE
  !error "Pass /DEXE=path\to\timenc-gui.exe"
!endif
!ifndef OUTFILE
  !define OUTFILE "TimENC_${VERSION}_x64-setup.exe"
!endif

!define APP "TimENC"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"
!define PROGID "TimENC.File"

Name "${APP}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\${APP}"
InstallDirRegKey HKCU "${UNINSTALL_KEY}" "InstallLocation"
RequestExecutionLevel user
SetCompressor /SOLID lzma
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP}"
VIAddVersionKey "FileDescription" "${APP} Setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "GPL-3.0, TimENC Contributors"

!define MUI_ICON "..\icons\icon.ico"
!define MUI_UNICON "..\icons\icon.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP}.exe"

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "German"

Section "Install"
  SetOutPath "$INSTDIR"
  ; Wait for a running TimENC to close before replacing it.
  ClearErrors
  Delete "$INSTDIR\${APP}.exe"
  IfErrors 0 +3
    MessageBox MB_OK|MB_ICONEXCLAMATION "Please close TimENC, then click OK." /SD IDOK
    Delete "$INSTDIR\${APP}.exe"
  ; Leftovers of the Tauri build.
  Delete "$INSTDIR\timenc-tauri.exe"
  RMDir /r "$INSTDIR\resources"

  File "/oname=${APP}.exe" "${EXE}"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\${APP}.lnk" "$INSTDIR\${APP}.exe"

  ; Double-click on .timenc files.
  WriteRegStr HKCU "Software\Classes\.timenc" "" "${PROGID}"
  WriteRegStr HKCU "Software\Classes\${PROGID}" "" "TimENC Encrypted File"
  WriteRegStr HKCU "Software\Classes\${PROGID}\DefaultIcon" "" "$INSTDIR\${APP}.exe,0"
  WriteRegStr HKCU "Software\Classes\${PROGID}\shell\open\command" "" '"$INSTDIR\${APP}.exe" "%1"'
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'

  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "TimENC Contributors"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\${APP}.exe"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\${APP}.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\${APP}.lnk"
  ReadRegStr $0 HKCU "Software\Classes\.timenc" ""
  StrCmp $0 "${PROGID}" 0 +2
    DeleteRegKey HKCU "Software\Classes\.timenc"
  DeleteRegKey HKCU "Software\Classes\${PROGID}"
  DeleteRegKey HKCU "${UNINSTALL_KEY}"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
SectionEnd
