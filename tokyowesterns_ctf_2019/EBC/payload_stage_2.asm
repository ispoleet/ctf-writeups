; --------------------------------------------------------------------------------------------------
; Decoded payload, stage 2
; --------------------------------------------------------------------------------------------------
0x04006354: 60 81 02 10                     MOVqw R1, @R0 (+2, +0)
0x04006358: f7 32 f2 28 f6 95 b8 75 5d bb   MOVIqq R2, 0xbb5d75b895f628f2
0x04006362: f7 33 8b 7b 73 c6 6e 28 0a d3   MOVIqq R3, 0xd30a286ec6737b8b
0x0400636c: f7 34 55 51 68 5d 0d 53 fa 1b   MOVIqq R4, 0x1bfa530d5d685155
0x04006376: f7 35 55 33 08 d2 b3 4d 9c a2   MOVIqq R5, 0xa29c4db3d2083355
0x04006380: f7 36 34 51 ff b2 83 0d 0a ab   MOVIqq R6, 0xab0a0d83b2ff5134
0x0400638a: f7 37 3d ab 69 e3 39 83 51 67   MOVIqq R7, 0x67518339e369ab3d
0x04006394: 4d 61                           SUB R1, R6
0x04006396: 56 51                           XOR R1, R5
0x04006398: f7 37 ae 52 b4 cb c4 98 12 da   MOVIqq R7, 0xda1298c4cbb452ae
0x040063a2: 20 17                           MOVqw R7, R1
0x040063a4: 77 35 27 00                     MOVIqw R5, 0x0027
0x040063a8: 57 57                           SHL R7, R5
0x040063aa: 77 35 19 00                     MOVIqw R5, 0x0019
0x040063ae: 58 51                           SHR R1, R5
0x040063b0: 55 71                           OR R1, R7
0x040063b2: f7 37 fe c8 c9 93 57 71 04 c6   MOVIqq R7, 0xc604715793c9c8fe
0x040063bc: f7 35 78 f0 c7 0d 45 0c f4 ac   MOVIqq R5, 0xacf40c450dc7f078
0x040063c6: 4d 31                           SUB R1, R3
0x040063c8: f7 37 30 61 59 cc 96 e6 94 91   MOVIqq R7, 0x9194e696cc596130
0x040063d2: 4a 11                           NOT R1, R1
0x040063d4: 20 15                           MOVqw R5, R1
0x040063d6: 77 33 03 00                     MOVIqw R3, 0x0003
0x040063da: 58 35                           SHR R5, R3
0x040063dc: 77 33 3d 00                     MOVIqw R3, 0x003d
0x040063e0: 57 31                           SHL R1, R3
0x040063e2: 55 51                           OR R1, R5
0x040063e4: f7 35 17 b7 d6 86 f5 5f 48 87   MOVIqq R5, 0x87485ff586d6b717
0x040063ee: f7 33 e2 74 7b c6 4c 9c a2 a9   MOVIqq R3, 0xa9a29c4cc67b74e2
0x040063f8: 20 15                           MOVqw R5, R1
0x040063fa: 77 37 02 00                     MOVIqw R7, 0x0002
0x040063fe: 57 75                           SHL R5, R7
0x04006400: 77 37 3e 00                     MOVIqw R7, 0x003e
0x04006404: 58 71                           SHR R1, R7
0x04006406: 55 51                           OR R1, R5
0x04006408: f7 35 e8 c8 08 a5 9f 9a dd 41   MOVIqq R5, 0x41dd9a9fa508c8e8
0x04006412: f7 37 39 08 19 11 db 0c 71 b5   MOVIqq R7, 0xb5710cdb11190839
0x0400641c: 20 13                           MOVqw R3, R1
0x0400641e: 77 32 1c 00                     MOVIqw R2, 0x001c
0x04006422: 58 23                           SHR R3, R2
0x04006424: 77 32 24 00                     MOVIqw R2, 0x0024
0x04006428: 57 21                           SHL R1, R2
0x0400642a: 55 31                           OR R1, R3
0x0400642c: f7 33 d2 ae 59 8a 91 f5 61 d5   MOVIqq R3, 0xd561f5918a59aed2
0x04006436: f7 32 17 ba 63 26 5d 85 53 6d   MOVIqq R2, 0x6d53855d2663ba17
0x04006440: 56 71                           XOR R1, R7
0x04006442: f7 36 fd f5 18 76 fc ab e8 58   MOVIqq R6, 0x58e8abfc7618f5fd
0x0400644c: 4b 11                           NEG R1, R1
0x0400644e: f7 36 69 7e b8 36 bb 91 07 31   MOVIqq R6, 0x310791bb36b87e69
0x04006458: 4d 51                           SUB R1, R5
0x0400645a: 4c 61                           ADD R1, R6
0x0400645c: 20 13                           MOVqw R3, R1
0x0400645e: 77 36 28 00                     MOVIqw R6, 0x0028
0x04006462: 57 63                           SHL R3, R6
0x04006464: 77 36 18 00                     MOVIqw R6, 0x0018
0x04006468: 58 61                           SHR R1, R6
0x0400646a: 55 31                           OR R1, R3
0x0400646c: f7 33 20 15 e3 6a 9e 0f 32 ef   MOVIqq R3, 0xef320f9e6ae31520
0x04006476: f7 36 bc 83 99 b2 2e b9 11 a1   MOVIqq R6, 0xa111b92eb29983bc
0x04006480: f7 35 c8 c7 2e 31 e6 a3 2c a4   MOVIqq R5, 0xa42ca3e6312ec7c8
0x0400648a: 20 17                           MOVqw R7, R1
0x0400648c: 77 35 32 00                     MOVIqw R5, 0x0032
0x04006490: 58 57                           SHR R7, R5
0x04006492: 77 35 0e 00                     MOVIqw R5, 0x000e
0x04006496: 57 51                           SHL R1, R5
0x04006498: 55 71                           OR R1, R7
0x0400649a: f7 37 62 3b be df 72 62 d3 5b   MOVIqq R7, 0x5bd36272dfbe3b62
0x040064a4: f7 35 1b 21 a8 70 48 f5 83 94   MOVIqq R5, 0x9483f54870a8211b
0x040064ae: 20 15                           MOVqw R5, R1
0x040064b0: 77 33 30 00                     MOVIqw R3, 0x0030
0x040064b4: 57 35                           SHL R5, R3
0x040064b6: 77 33 10 00                     MOVIqw R3, 0x0010
0x040064ba: 58 31                           SHR R1, R3
0x040064bc: 55 51                           OR R1, R5
0x040064be: f7 35 0c 9d bc 00 db f7 ad 57   MOVIqq R5, 0x57adf7db00bc9d0c
0x040064c8: f7 33 e2 e2 5c d7 a2 e8 87 ee   MOVIqq R3, 0xee87e8a2d75ce2e2
0x040064d2: f7 36 e3 ee 36 3e cb b0 21 4d   MOVIqq R6, 0x4d21b0cb3e36eee3
0x040064dc: 4d 61                           SUB R1, R6
0x040064de: f7 33 8a 71 4c ac f8 07 44 f3   MOVIqq R3, 0xf34407f8ac4c718a
0x040064e8: 4d 51                           SUB R1, R5
0x040064ea: 20 14                           MOVqw R4, R1
0x040064ec: 77 32 0a 00                     MOVIqw R2, 0x000a
0x040064f0: 58 24                           SHR R4, R2
0x040064f2: 77 32 36 00                     MOVIqw R2, 0x0036
0x040064f6: 57 21                           SHL R1, R2
0x040064f8: 55 41                           OR R1, R4
0x040064fa: f7 34 27 af 5b 31 9e 1f 8e 29   MOVIqq R4, 0x298e1f9e315baf27
0x04006504: f7 32 12 eb 99 cc 08 d4 ce 70   MOVIqq R2, 0x70ced408cc99eb12
0x0400650e: 20 13                           MOVqw R3, R1
0x04006510: 77 36 17 00                     MOVIqw R6, 0x0017
0x04006514: 57 63                           SHL R3, R6
0x04006516: 77 36 29 00                     MOVIqw R6, 0x0029
0x0400651a: 58 61                           SHR R1, R6
0x0400651c: 55 31                           OR R1, R3
0x0400651e: f7 33 af 8f ed 03 81 13 58 e8   MOVIqq R3, 0xe858138103ed8faf
0x04006528: f7 36 d6 8c 64 32 19 3d 46 1b   MOVIqq R6, 0x1b463d1932648cd6
0x04006532: f7 35 a3 01 09 e5 1b 12 12 0f   MOVIqq R5, 0x0f12121be50901a3
0x0400653c: 4d 61                           SUB R1, R6
0x0400653e: f7 35 23 05 1c 79 99 a3 9b be   MOVIqq R5, 0xbe9ba399791c0523
0x04006548: 4b 11                           NEG R1, R1
0x0400654a: f7 35 a5 2c db 22 10 3f 64 5c   MOVIqq R5, 0x5c643f1022db2ca5
0x04006554: 56 21                           XOR R1, R2
0x04006556: 20 17                           MOVqw R7, R1
0x04006558: 77 32 23 00                     MOVIqw R2, 0x0023
0x0400655c: 57 27                           SHL R7, R2
0x0400655e: 77 32 1d 00                     MOVIqw R2, 0x001d
0x04006562: 58 21                           SHR R1, R2
0x04006564: 55 71                           OR R1, R7
0x04006566: f7 37 76 bf a5 ea 13 ff 7c 49   MOVIqq R7, 0x497cff13eaa5bf76
0x04006570: f7 32 0f 41 84 b0 b1 e3 28 eb   MOVIqq R2, 0xeb28e3b1b084410f
0x0400657a: 4c 41                           ADD R1, R4
0x0400657c: f7 35 25 a1 a0 6f a7 2b 88 9f   MOVIqq R5, 0x9f882ba76fa0a125
0x04006586: 20 13                           MOVqw R3, R1
0x04006588: 77 34 2b 00                     MOVIqw R4, 0x002b
0x0400658c: 57 43                           SHL R3, R4
0x0400658e: 77 34 15 00                     MOVIqw R4, 0x0015
0x04006592: 58 41                           SHR R1, R4
0x04006594: 55 31                           OR R1, R3
0x04006596: f7 33 65 b2 0a 2f bd 42 84 30   MOVIqq R3, 0x308442bd2f0ab265
0x040065a0: f7 34 92 8c d0 6c 71 43 67 30   MOVIqq R4, 0x306743716cd08c92
0x040065aa: 20 16                           MOVqw R6, R1
0x040065ac: 77 32 0e 00                     MOVIqw R2, 0x000e
0x040065b0: 58 26                           SHR R6, R2
0x040065b2: 77 32 32 00                     MOVIqw R2, 0x0032
0x040065b6: 57 21                           SHL R1, R2
0x040065b8: 55 61                           OR R1, R6
0x040065ba: f7 36 6f de 5b 9a a0 b4 01 d7   MOVIqq R6, 0xd701b4a09a5bde6f
0x040065c4: f7 32 51 07 a1 2f 3c ac d3 6f   MOVIqq R2, 0x6fd3ac3c2fa10751
0x040065ce: f7 37 0f b9 f2 8b ff 1d a1 c1   MOVIqq R7, 0xc1a11dff8bf2b90f
0x040065d8: 4b 11                           NEG R1, R1
0x040065da: 20 12                           MOVqw R2, R1
0x040065dc: 77 36 1f 00                     MOVIqw R6, 0x001f
0x040065e0: 58 62                           SHR R2, R6
0x040065e2: 77 36 21 00                     MOVIqw R6, 0x0021
0x040065e6: 57 61                           SHL R1, R6
0x040065e8: 55 21                           OR R1, R2
0x040065ea: f7 32 5b d0 c9 d3 fd d9 e7 fe   MOVIqq R2, 0xfee7d9fdd3c9d05b
0x040065f4: f7 36 87 b5 53 06 8c da f5 c6   MOVIqq R6, 0xc6f5da8c0653b587
0x040065fe: 20 16                           MOVqw R6, R1
0x04006600: 77 32 22 00                     MOVIqw R2, 0x0022
0x04006604: 58 26                           SHR R6, R2
0x04006606: 77 32 1e 00                     MOVIqw R2, 0x001e
0x0400660a: 57 21                           SHL R1, R2
0x0400660c: 55 61                           OR R1, R6
0x0400660e: f7 36 4d a8 61 b2 2f d4 27 f3   MOVIqq R6, 0xf327d42fb261a84d
0x04006618: f7 32 39 3e f7 65 64 87 a4 fa   MOVIqq R2, 0xfaa4876465f73e39
0x04006622: 4a 11                           NOT R1, R1
0x04006624: 20 17                           MOVqw R7, R1
0x04006626: 77 36 06 00                     MOVIqw R6, 0x0006
0x0400662a: 57 67                           SHL R7, R6
0x0400662c: 77 36 3a 00                     MOVIqw R6, 0x003a
0x04006630: 58 61                           SHR R1, R6
0x04006632: 55 71                           OR R1, R7
0x04006634: f7 37 bd 7c d8 82 fd 32 d9 f4   MOVIqq R7, 0xf4d932fd82d87cbd
0x0400663e: f7 36 07 67 2d 5f 4e 02 45 08   MOVIqq R6, 0x0845024e5f2d6707
0x04006648: f7 33 37 76 ed 9e 5c ad a2 68   MOVIqq R3, 0x68a2ad5c9eed7637
0x04006652: 4c 51                           ADD R1, R5
0x04006654: f7 34 4c 2b 9f 99 10 6d bd e0   MOVIqq R4, 0xe0bd6d10999f2b4c
0x0400665e: 56 51   XOR R1, R5
0x04006660: f7 37 e1 8a ff 7b bf ec b5 41   MOVIqq R7, 0x41b5ecbf7bff8ae1
0x0400666a: 4c 61                           ADD R1, R6
0x0400666c: 4c 61                           ADD R1, R6
0x0400666e: f7 35 dd 0a 0a 5a 6f ef a7 1f   MOVIqq R5, 0x1fa7ef6f5a0a0add
0x04006678: 4d 21                           SUB R1, R2
0x0400667a: 20 15                           MOVqw R5, R1
0x0400667c: 77 34 3d 00                     MOVIqw R4, 0x003d
0x04006680: 58 45                           SHR R5, R4
0x04006682: 77 34 03 00                     MOVIqw R4, 0x0003
0x04006686: 57 41                           SHL R1, R4
0x04006688: 55 51                           OR R1, R5
0x0400668a: f7 35 c7 a5 40 5c bb 2d 9e b6   MOVIqq R5, 0xb69e2dbb5c40a5c7
0x04006694: f7 34 ae e3 0f 3e 39 fc b5 19   MOVIqq R4, 0x19b5fc393e0fe3ae
0x0400669e: 56 71                           XOR R1, R7
0x040066a0: 56 31                           XOR R1, R3
0x040066a2: 20 15                           MOVqw R5, R1
0x040066a4: 77 32 15 00                     MOVIqw R2, 0x0015
0x040066a8: 58 25                           SHR R5, R2
0x040066aa: 77 32 2b 00                     MOVIqw R2, 0x002b
0x040066ae: 57 21                           SHL R1, R2
0x040066b0: 55 51                           OR R1, R5
0x040066b2: f7 35 5d ab cb 23 d5 51 9f 6d   MOVIqq R5, 0x6d9f51d523cbab5d
0x040066bc: f7 32 ab 0a 55 cb 9f 91 21 91   MOVIqq R2, 0x9121919fcb550aab
0x040066c6: f7 34 5e 03 74 84 bf 3d 9b a8   MOVIqq R4, 0xa89b3dbf8474035e
0x040066d0: 4c 51                           ADD R1, R5
0x040066d2: 56 61                           XOR R1, R6
0x040066d4: f7 35 b2 09 65 68 85 50 0a 90   MOVIqq R5, 0x900a5085686509b2
0x040066de: 20 15                           MOVqw R5, R1
0x040066e0: 77 34 30 00                     MOVIqw R4, 0x0030
0x040066e4: 57 45                           SHL R5, R4
0x040066e6: 77 34 10 00                     MOVIqw R4, 0x0010
0x040066ea: 58 41                           SHR R1, R4
0x040066ec: 55 51                           OR R1, R5
0x040066ee: f7 35 14 47 b4 2d 55 c3 84 13   MOVIqq R5, 0x1384c3552db44714
0x040066f8: f7 34 9a 32 ab 54 0a 12 17 21   MOVIqq R4, 0x2117120a54ab329a
0x04006702: 56 51                           XOR R1, R5
0x04006704: f7 35 e4 e9 18 1f 5d b9 ae a7   MOVIqq R5, 0xa7aeb95d1f18e9e4
0x0400670e: 4d 61                           SUB R1, R6
0x04006710: 20 15                           MOVqw R5, R1
0x04006712: 77 36 14 00                     MOVIqw R6, 0x0014
0x04006716: 57 65                           SHL R5, R6
0x04006718: 77 36 2c 00                     MOVIqw R6, 0x002c
0x0400671c: 58 61                           SHR R1, R6
0x0400671e: 55 51                           OR R1, R5
0x04006720: f7 35 c5 b1 95 62 4f ff ec b9   MOVIqq R5, 0xb9ecff4f6295b1c5
0x0400672a: f7 36 3a de ad 9f 9c 75 73 83   MOVIqq R6, 0x8373759c9fadde3a
0x04006734: 4b 11                           NEG R1, R1
0x04006736: 4d 21                           SUB R1, R2
0x04006738: 4c 61                           ADD R1, R6
0x0400673a: 4a 11                           NOT R1, R1
0x0400673c: 4a 11                           NOT R1, R1
0x0400673e: 20 15                           MOVqw R5, R1
0x04006740: 77 37 31 00                     MOVIqw R7, 0x0031
0x04006744: 58 75                           SHR R5, R7
0x04006746: 77 37 0f 00                     MOVIqw R7, 0x000f
0x0400674a: 57 71                           SHL R1, R7
0x0400674c: 55 51                           OR R1, R5
0x0400674e: f7 35 10 a9 e3 9d d2 9a 7a d2   MOVIqq R5, 0xd27a9ad29de3a910
0x04006758: f7 37 9b 7d ec 57 1d 6a da ea   MOVIqq R7, 0xeada6a1d57ec7d9b
0x04006762: 20 16                           MOVqw R6, R1
0x04006764: 77 32 27 00                     MOVIqw R2, 0x0027
0x04006768: 57 26                           SHL R6, R2
0x0400676a: 77 32 19 00                     MOVIqw R2, 0x0019
0x0400676e: 58 21                           SHR R1, R2
0x04006770: 55 61                           OR R1, R6
0x04006772: f7 36 79 32 a7 19 cd f2 e8 6f   MOVIqq R6, 0x6fe8f2cd19a73279
0x0400677c: f7 32 c9 b2 38 66 0f df b3 3a   MOVIqq R2, 0x3ab3df0f6638b2c9
0x04006786: 4b 11                           NEG R1, R1
0x04006788: f7 36 34 f7 fe 2e 20 fb 1d 67   MOVIqq R6, 0x671dfb202efef734
0x04006792: 4c 51                           ADD R1, R5
0x04006794: f7 33 35 6e 23 43 ce d6 45 50   MOVIqq R3, 0x5045d6ce43236e35
0x0400679e: 4a 11                           NOT R1, R1
0x040067a0: f7 33 6c 8b 37 7a 77 11 b1 64   MOVIqq R3, 0x64b111777a378b6c
0x040067aa: 20 16                           MOVqw R6, R1
0x040067ac: 77 35 11 00                     MOVIqw R5, 0x0011
0x040067b0: 58 56                           SHR R6, R5
0x040067b2: 77 35 2f 00                     MOVIqw R5, 0x002f
0x040067b6: 57 51                           SHL R1, R5
0x040067b8: 55 61                           OR R1, R6
0x040067ba: f7 36 c7 2e 88 ab 8e 12 aa ba   MOVIqq R6, 0xbaaa128eab882ec7
0x040067c4: f7 35 27 4e 1b ac e0 1e 13 76   MOVIqq R5, 0x76131ee0ac1b4e27
0x040067ce: 56 71                           XOR R1, R7
0x040067d0: 4d 71                           SUB R1, R7
0x040067d2: 56 41                           XOR R1, R4
0x040067d4: 56 51                           XOR R1, R5
0x040067d6: 56 31                           XOR R1, R3
0x040067d8: f7 34 c1 3e ad 6a 80 64 4e 6f   MOVIqq R4, 0x6f4e64806aad3ec1
0x040067e2: 4c 61                           ADD R1, R6
0x040067e4: 20 14                           MOVqw R4, R1
0x040067e6: 77 37 31 00                     MOVIqw R7, 0x0031
0x040067ea: 58 74                           SHR R4, R7
0x040067ec: 77 37 0f 00                     MOVIqw R7, 0x000f
0x040067f0: 57 71                           SHL R1, R7
0x040067f2: 55 41                           OR R1, R4
0x040067f4: f7 34 be 8b a0 ef b5 f5 e4 3e   MOVIqq R4, 0x3ee4f5b5efa08bbe
0x040067fe: f7 37 7d e4 68 5e a4 81 e0 43   MOVIqq R7, 0x43e081a45e68e47d
0x04006808: 20 17                           MOVqw R7, R1
0x0400680a: 77 32 14 00                     MOVIqw R2, 0x0014
0x0400680e: 58 27                           SHR R7, R2
0x04006810: 77 32 2c 00                     MOVIqw R2, 0x002c
0x04006814: 57 21                           SHL R1, R2
0x04006816: 55 71                           OR R1, R7
0x04006818: f7 37 06 e1 c6 eb 13 e3 83 1c   MOVIqq R7, 0x1c83e313ebc6e106
0x04006822: f7 32 2f 3e 18 f3 89 80 af f7   MOVIqq R2, 0xf7af8089f3183e2f
0x0400682c: 4c 31                           ADD R1, R3
0x0400682e: 20 17                           MOVqw R7, R1
0x04006830: 77 34 28 00                     MOVIqw R4, 0x0028
0x04006834: 57 47                           SHL R7, R4
0x04006836: 77 34 18 00                     MOVIqw R4, 0x0018
0x0400683a: 58 41                           SHR R1, R4
0x0400683c: 55 71                           OR R1, R7
0x0400683e: f7 37 93 cd 3c 80 ff 27 e2 21   MOVIqq R7, 0x21e227ff803ccd93
0x04006848: f7 34 11 50 91 d4 f5 05 61 fb   MOVIqq R4, 0xfb6105f5d4915011
0x04006852: f7 32 0b 7c 52 ab 31 76 4f 20   MOVIqq R2, 0x204f7631ab527c0b
0x0400685c: 4c 71                           ADD R1, R7
0x0400685e: f7 32 6c f8 a1 b8 e6 e0 29 a0   MOVIqq R2, 0xa029e0e6b8a1f86c
0x04006868: 4c 31                           ADD R1, R3
0x0400686a: f7 35 4e 09 52 40 3d c3 eb 6d   MOVIqq R5, 0x6debc33d4052094e
0x04006874: 4c 71                           ADD R1, R7
0x04006876: 56 31                           XOR R1, R3
0x04006878: 56 71                           XOR R1, R7
0x0400687a: f7 35 6a 16 05 75 ec ce 0d 21   MOVIqq R5, 0x210dceec7505166a
0x04006884: 4c 41                           ADD R1, R4
0x04006886: 56 51                           XOR R1, R5
0x04006888: f7 32 57 41 a4 95 c6 a7 72 9c   MOVIqq R2, 0x9c72a7c695a44157
0x04006892: 4d 21                           SUB R1, R2
0x04006894: 4c 31                           ADD R1, R3
0x04006896: f7 37 a5 ef 38 8f aa 81 1a b8   MOVIqq R7, 0xb81a81aa8f38efa5
0x040068a0: 56 41                           XOR R1, R4
0x040068a2: f7 33 3a cd f9 a3 30 ed 95 86   MOVIqq R3, 0x8695ed30a3f9cd3a
0x040068ac: 20 14                           MOVqw R4, R1
0x040068ae: 77 32 0f 00                     MOVIqw R2, 0x000f
0x040068b2: 58 24                           SHR R4, R2
0x040068b4: 77 32 31 00                     MOVIqw R2, 0x0031
0x040068b8: 57 21                           SHL R1, R2
0x040068ba: 55 41                           OR R1, R4
0x040068bc: f7 34 80 46 bb 4b e8 6b 1f ad   MOVIqq R4, 0xad1f6be84bbb4680
0x040068c6: f7 32 7d c6 e3 51 08 1a 37 c5   MOVIqq R2, 0xc5371a0851e3c67d
0x040068d0: 4c 51                           ADD R1, R5
0x040068d2: f7 37 eb 13 b2 cc 11 34 e7 7f   MOVIqq R7, 0x7fe73411ccb213eb
0x040068dc: 4c 71                           ADD R1, R7
0x040068de: 20 13                           MOVqw R3, R1
0x040068e0: 77 37 22 00                     MOVIqw R7, 0x0022
0x040068e4: 57 73                           SHL R3, R7
0x040068e6: 77 37 1e 00                     MOVIqw R7, 0x001e
0x040068ea: 58 71                           SHR R1, R7
0x040068ec: 55 31                           OR R1, R3
0x040068ee: f7 33 c5 ec cf fc 2d 0e b2 de   MOVIqq R3, 0xdeb20e2dfccfecc5
0x040068f8: f7 37 87 6c c3 1d 4e 53 e1 b5   MOVIqq R7, 0xb5e1534e1dc36c87
0x04006902: f7 35 ef 78 83 65 92 bd e1 d6   MOVIqq R5, 0xd6e1bd92658378ef
0x0400690c: 4c 41                           ADD R1, R4
0x0400690e: f7 33 f1 e4 a1 38 d8 9e 3d be   MOVIqq R3, 0xbe3d9ed838a1e4f1
0x04006918: 4d 51                           SUB R1, R5
0x0400691a: 4c 41                           ADD R1, R4
0x0400691c: f7 36 27 cd f1 61 39 fa 82 58   MOVIqq R6, 0x5882fa3961f1cd27
0x04006926: 20 14                           MOVqw R4, R1
0x04006928: 77 36 07 00                     MOVIqw R6, 0x0007
0x0400692c: 58 64                           SHR R4, R6
0x0400692e: 77 36 39 00                     MOVIqw R6, 0x0039
0x04006932: 57 61                           SHL R1, R6
0x04006934: 55 41                           OR R1, R4
0x04006936: f7 34 67 4f b5 57 45 ac 6c 82   MOVIqq R4, 0x826cac4557b54f67
0x04006940: f7 36 ab 0d 46 0c 80 5b 00 39   MOVIqq R6, 0x39005b800c460dab
0x0400694a: f7 37 fd ed 7f 1e f8 47 9b 9f   MOVIqq R7, 0x9f9b47f81e7fedfd
0x04006954: 4d 61                           SUB R1, R6
0x04006956: 20 16                           MOVqw R6, R1
0x04006958: 77 34 15 00                     MOVIqw R4, 0x0015
0x0400695c: 58 46                           SHR R6, R4
0x0400695e: 77 34 2b 00                     MOVIqw R4, 0x002b
0x04006962: 57 41                           SHL R1, R4
0x04006964: 55 61                           OR R1, R6
0x04006966: f7 36 6e 2f c9 52 d5 74 87 c9   MOVIqq R6, 0xc98774d552c92f6e
0x04006970: f7 34 c0 46 f3 cc cb ee 68 8c   MOVIqq R4, 0x8c68eecbccf346c0
0x0400697a: f7 33 0a 3d 54 cb f0 55 97 d6   MOVIqq R3, 0xd69755f0cb543d0a
0x04006984: 4a 11                           NOT R1, R1
0x04006986: f7 33 d3 92 09 5a 0d f1 7f a0   MOVIqq R3, 0xa07ff10d5a0992d3
0x04006990: 4d 41                           SUB R1, R4
0x04006992: 56 71                           XOR R1, R7
0x04006994: f7 36 33 b6 3a 88 cb b1 d3 fa   MOVIqq R6, 0xfad3b1cb883ab633
0x0400699e: 4a 11                           NOT R1, R1
0x040069a0: 20 14                           MOVqw R4, R1
0x040069a2: 77 35 1a 00                     MOVIqw R5, 0x001a
0x040069a6: 58 54                           SHR R4, R5
0x040069a8: 77 35 26 00                     MOVIqw R5, 0x0026
0x040069ac: 57 51                           SHL R1, R5
0x040069ae: 55 41                           OR R1, R4
0x040069b0: f7 34 97 3f 47 52 95 e9 5f 32   MOVIqq R4, 0x325fe99552473f97
0x040069ba: f7 35 64 0a eb b9 ed f6 1c e1   MOVIqq R5, 0xe11cf6edb9eb0a64
0x040069c4: f7 35 21 9d 3c f1 ce 7b b5 16   MOVIqq R5, 0x16b57bcef13c9d21
0x040069ce: 20 13                           MOVqw R3, R1
0x040069d0: 77 32 10 00                     MOVIqw R2, 0x0010
0x040069d4: 57 23                           SHL R3, R2
0x040069d6: 77 32 30 00                     MOVIqw R2, 0x0030
0x040069da: 58 21                           SHR R1, R2
0x040069dc: 55 31                           OR R1, R3
0x040069de: f7 33 12 02 41 bd 03 d9 b6 dd   MOVIqq R3, 0xddb6d903bd410212
0x040069e8: f7 32 9a b7 9f ad 87 b6 a1 ac   MOVIqq R2, 0xaca1b687ad9fb79a
0x040069f2: f7 35 58 05 a1 f6 cd 5c 1d ec   MOVIqq R5, 0xec1d5ccdf6a10558
0x040069fc: 20 16                           MOVqw R6, R1
0x040069fe: 77 33 32 00                     MOVIqw R3, 0x0032
0x04006a02: 58 36                           SHR R6, R3
0x04006a04: 77 33 0e 00                     MOVIqw R3, 0x000e
0x04006a08: 57 31                           SHL R1, R3
0x04006a0a: 55 61                           OR R1, R6
0x04006a0c: f7 36 a1 aa 96 d3 f9 db d4 79   MOVIqq R6, 0x79d4dbf9d396aaa1
0x04006a16: f7 33 53 67 b3 09 9d f6 e2 d5   MOVIqq R3, 0xd5e2f69d09b36753
0x04006a20: 4c 21                           ADD R1, R2
0x04006a22: 4a 11                           NOT R1, R1
0x04006a24: 20 15                           MOVqw R5, R1
0x04006a26: 77 36 2e 00                     MOVIqw R6, 0x002e
0x04006a2a: 57 65                           SHL R5, R6
0x04006a2c: 77 36 12 00                     MOVIqw R6, 0x0012
0x04006a30: 58 61                           SHR R1, R6
0x04006a32: 55 51                           OR R1, R5
0x04006a34: f7 35 01 42 a7 50 6f 64 b3 3b   MOVIqq R5, 0x3bb3646f50a74201
0x04006a3e: f7 36 bd f7 b3 07 42 4e 67 7a   MOVIqq R6, 0x7a674e4207b3f7bd
0x04006a48: f7 33 e2 bb ec d9 e6 94 f1 25   MOVIqq R3, 0x25f194e6d9ecbbe2
0x04006a52: 56 71                           XOR R1, R7
0x04006a54: f7 34 5a 8b dc 38 48 9f d8 03   MOVIqq R4, 0x03d89f4838dc8b5a
0x04006a5e: 20 13                           MOVqw R3, R1
0x04006a60: 77 32 11 00                     MOVIqw R2, 0x0011
0x04006a64: 57 23                           SHL R3, R2
0x04006a66: 77 32 2f 00                     MOVIqw R2, 0x002f
0x04006a6a: 58 21                           SHR R1, R2
0x04006a6c: 55 31                           OR R1, R3
0x04006a6e: f7 33 36 51 8e 8c ce de 5c e6   MOVIqq R3, 0xe65cdece8c8e5136
0x04006a78: f7 32 77 51 2d af 1d ec aa ee   MOVIqq R2, 0xeeaaec1daf2d5177
0x04006a82: f7 34 8e 36 b0 c6 1e c6 1d 45   MOVIqq R4, 0x451dc61ec6b0368e
0x04006a8c: 4d 71                           SUB R1, R7
0x04006a8e: f7 37 61 97 4d 99 5e 4b a6 0f   MOVIqq R7, 0x0fa64b5e994d9761
0x04006a98: 45 71                           CMPeq R1, R7
0x04006a9a: 82 03                           JMP8cc 0x03
0x04006a9c: 77 31 01 00                     MOVIqw R1, 0x0001
0x04006aa0: 02 02                           JMP8 0x02
0x04006aa2: 77 31 00 00                     MOVIqw R1, 0x0000
0x04006aa6: 20 17                           MOVqw R7, R1
0x04006aa8: 04 00                           RET
