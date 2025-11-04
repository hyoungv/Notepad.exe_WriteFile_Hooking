# Notepad.exe WriteFile_Hooking
 이 실습은 사용자 정의 DLL을 타킷 프로세스(notepad.exe)에 주입하고, WriteFile을 MinHook으로 후킹해 데이터 내용을 로그로 남기는 실습과 디버거 방식을 이용하여 후킹하는 실습 두가지를 비교한다.

 MinHook 기반 DLL 후킹으로 원리, 수정, 로깅을 익힌 뒤에 보충으로 디버거(브레이크포인트) 방식으로 메모리 관찰/디버깅 이벤트 흐름을 확인하였다. 

 A. MinHook + DLL 주입 방식 
 - HookDll.dll  
 - Injector.exe 
 - notepad_writefile_hook.log 
 - HookDll.cpp : 후킹 DLL(MinHook 사용)
 - Injector.cpp 

<실습 순서>
  1. notepad.exe 실행 후 notepad PID 확인하여 관리자 권한 powershell로 Injector 실행. 
  2. Injector 콘솔에 "Injection succeeded" 성공 메시지 확인.
  3. notepad_writefile_hook.log.txt를 통해 "[HookDll] hooks installed" 설치 성공 표시 확인 후,   WriteFile 호출마다 헥스/ASCII 추가됨. 
  4. 동작 검증은 Notepad에서 텍스트 입력 및 저장 후 로그 확인. 그리고 Process Explorer로 notepad 프로세스 모듈에 HookDll.dll 로드 되었는지 확인
