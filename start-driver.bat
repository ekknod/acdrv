sc create acdriver binPath="%~dp0\x64\Release\acdriver.sys" type=kernel
sc start acdriver
pause
sc stop acdriver
sc delete acdriver  