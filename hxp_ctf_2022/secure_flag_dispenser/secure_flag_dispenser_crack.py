#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP 2022 - Secure Flag Dispenser (Misc/RE/Crypto 417)
# ----------------------------------------------------------------------------------------
import scapy.all
from Crypto.Cipher import AES


# ----------------------------------------------------------------------------------------
def get_all_ips():
    """Extracts all IPs from the pcap file."""
    all_ips = set()

    pcap_flow = scapy.all.rdpcap('t.pcap')
    sessions = pcap_flow.sessions()    
    for session in sessions:
        for i, packet in enumerate(sessions[session]):
            try:          
                all_ips.add(packet[scapy.all.IP].src)
                all_ips.add(packet[scapy.all.IP].dst)
            except Exception as e:
                pass

    for ip in all_ips:
        print(f'[+] IP found: {ip}')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Secure Flag Dispenser crack started.')

    get_all_ips()

    pcap_flow = scapy.all.rdpcap('t.pcap')
    sessions = pcap_flow.sessions()    
    j = 0
    for session in sessions:
        print('session', session)
        for i, packet in enumerate(sessions[session]):
            try:                
                # Select traffic that comes from server to the "crappy" domain.
                if (packet[scapy.all.IP].src == '46.226.106.54' and
                    packet[scapy.all.IP].dst == '92.243.26.60'  and
                    'P' in packet[scapy.all.TCP].flags):   # PUSH flag is set, so we have data

                    payload = bytes(packet[scapy.all.TCP].payload).strip()
                    print(f"[+] {j:4}: {payload.decode('utf-8')}")

                    j += 1
            except Exception as e:
                pass


    # Select any lowercase ciphertext of length 128.
    cipher = 'e86ff18a103d528ac01d0fbba5d55491f678ee3a7c6dd53135243ddf2e7852b7daa32347eaad1c6c869d6d569e366578c0a442da2e091a24eed12b1e7772a9fb'
    cipher = 'b9058638622df4e3bb39dcd056394fbbb6a0af5ddb7dc98ffca30584b6320f0f5d8d0ad9d127b5d4a7ba1d355b71f4ff13e6bcd9ede5851cafef176cb2a8f882'

    print(f'[+] Cracking ciphertext: {cipher}')

    for a in range(0, 256):
        print(f'[+] Trying a = {a} ...')
        for b in range(0, 256):
            for c in range(0, 256):
                key = bytes([ord('.')]*13 + [a, b, c])                
                crypto = AES.new(key=key, IV=b'hxp{n0t_4_fl4g}\0', mode=AES.MODE_CBC)
                plain = crypto.decrypt(bytes.fromhex(cipher))            
                plain = ''.join('%c' % x for x in plain)

                if plain.startswith('hxp{'):
                    print(f"[+] Key  FOUND: {'-'.join(f'{k:02X}' for k in key)}")
                    print(f"[+] Flag FOUND: {plain}")
                    exit()

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
"""
ispo@ispo-glaptop2:~/ctf/hxp_2022/secure_flag_dispenser$ ./secure_flag_dispenser_crack.py 
[+] Secure Flag Dispenser crack started.
[+] IP found: 46.226.106.30
[+] IP found: 92.243.26.60
[+] IP found: 46.226.106.54
session Other
[+]    0: 27B9762C195D96C8FB3F7B7F11D5090B6F85453D7F0FD482CE134BE6D752840E00272F2E81043C3D7A75FD9BF3FED8246F542A0DBC57824E72366A5A2D1D9CAA7AAE5E3F53AD67811978A3666126143690FC634ACCBDAA8CB8D850D6EC3463611D1A0E404BA0433B81C2C3086C7DAFAD849A19227C897FE11309FC0505A202DA
[+]    1: e86ff18a103d528ac01d0fbba5d55491f678ee3a7c6dd53135243ddf2e7852b7daa32347eaad1c6c869d6d569e366578c0a442da2e091a24eed12b1e7772a9fb
[+]    2: 2BDDB682E0D0EF89EE20AE617100F46A889F70CFC00054DD8A7BB0EC82E729A87B94515B7F66507C54DF5416964B280E2A2B77EFAAF8ED979726E14B47E97C88F4B563291931441C782EFB33EA1A5D63A8B2A7608BE9242B3CFEC85085B82C2AC193172E01DD4A80104D4D48063A0A676BDA97841402CAC6D0E8DFBECB13A40B
[+]    3: 4f76ea7dea29ea09db6c318616e329076e0d234fa9c249f801419b3b020f2e96efa0ccf696e934d1bd67a4a095cc522aabe7a4a3b002175c4a418da4ce9083c8
[+]    4: 2D63E11A0EA77FE86A5E2DEA790FA2539F1497DDEE6ECB1642E090E1B4FB0A52ECC71E7ADAE3A88FE452901D95F5535F51DF9F776CF39FCF60FBD6F66013F5A5E81CFB76222241D7C94C6C06CA2719A3CDFFD99B5ED35208F14150481E50F698E9E6C2D7D45CAB2A0D97F54EFDDF2878ADDB2F8223C4CCB3FF1C71D9079E036E
[+]    5: b9058638622df4e3bb39dcd056394fbbb6a0af5ddb7dc98ffca30584b6320f0f5d8d0ad9d127b5d4a7ba1d355b71f4ff13e6bcd9ede5851cafef176cb2a8f882
[+]    6: 2007661554F308BA91DB2B686FBA7AEC8183AEA37964EAD6E2E89D517061BDAFF981752D8E9CCE1A1F668FA04F9BB8E2444DDBAA3F86CB09DD97EF3081487F6700F7EB7E142682929BBAE0A22B25B6712E13BAFA559505D0142D22F1BEE6E18AE84AF36BF1B4D07330A3CF162A90B96FA070C13B60C04304216649812B825989
[+]    7: b4678af76aa353c1988697821016cca6acc5729c3bea8b8b3a8f1403298a95b673fa198b
[+]    8: c4674a19bc4085f4e7a0fa20bb15f9cfe0c16877509418e890fdaa22
[+]    9: 011B261819A1D2E16B92AE55883C4957F1DC921B16204F851E3C3D9C10E3F5125BD361CCFE9AA08D29A091084D5989E1C2E9003765D2DD61A10386B96843E4E52BACD32AE44FDFFDF1A9676B646B0BD34C5A1A48FF3D4DE74F8D04A26DC32B0FA4B0B1789496B4A49E655B22CC269ED39A74667E73E0A03DEF3C45AECD9C248D
[+]   10: 98356b7043e084e663dbdb0e419dd65f79704e6584c7edf25fbaf433eff0b855ac340138a57b5be9e7592de85fbfdf282580c219a6d01b65e32f6620479354
[+]   11: b8
....
[+] 1121: 22395ada825b85d4672b481603b4e12c3206f4ca995ccb59d5b1e3
[+] 1122: cfbadf755af45d9ae28614279d222b0148a017ead1100af839ef1c3654
[+] 1123: 582474a69ce94c81
[+] 1124: 4D41A4EC2C1DB94790FBE2A5F670E4FADACF6942F91549DE0A610FD9999FCB1C2400B9A24205A998A9BD723955A9701B3A8EAA36C09D1C1929508BA49876F79D3BE3354B707C18ABB9CD67B0062BDA7B5F547FEF414C0BAD1B69051350C68D6E5AD71287A00B04E818B1C1C978356A7C1F8FF044180F5B426C76D95F24DE6E2D
[+] 1125: 999ea867a5efa0412cb76c8f2399ac791c94f9fac70dd95bb26eb30ffdd2d57dbacb69117350c4e9dc37af259573176438682dde90ac8340c3b722f3473ce887
[+] 1126: 272757E3AB7657006FFA8E79BAE9065B848209273DA63EF6DDFC3C42A9D28049D8D57DA19AE267FA458DAF38F71EB5FF4BF843FFCE325886142F8735087EA7A57B59365E518B7777D35136EE0A221AB6D737EBDE6C52524C8B4361745625B486CCD6DF2CF79F291DC0FED4DE0A32D519C6EEFCF2E85F143C10EF0F3A47BE3A7D
[+] 1127: eecffea772980db8df7d4d1f546597b3937d0013c2ba5441fe9e308d234ea325d06d93d902a9
[+] 1128: ac742270a458f3df4ba90387474ea21ddb2b98685473260014ec
[+] 1129: 4B3AF011C84D0DE1B82F7E85C4B192D3E135E880B13EFC60FFE04A3F2FD5A9FD10A5814D21008857A6B2F15B771F51942C6193468B0F307A0713AD99FDE0CC928CF9105A9AA7F016F6127588ED02AE69F26436EE2D1C5C9F984B3B377BA7B4F63F1F5FBF92BCAB5DC59CCCDC7884B0F25B9AE2072580FB9F21D2777DAEA3D2E6
[+] 1130: 8f946e7b0bfedc20f491268a9c3520e110ab41c41c525ade8e1290d59f5b6a5fe77e3a3cfe
[+] 1131: 97b210d7ecc4df251dffbb4cee04a0b4225e59d0541546f742200a
[+] Cracking ciphertext: b9058638622df4e3bb39dcd056394fbbb6a0af5ddb7dc98ffca30584b6320f0f5d8d0ad9d127b5d4a7ba1d355b71f4ff13e6bcd9ede5851cafef176cb2a8f882
[+] Trying a = 0 ...
[+] Trying a = 1 ...
[+] Trying a = 2 ...
[+] Trying a = 3 ...
[+] Trying a = 4 ...
....
[+] Trying a = 72 ...
[+] Trying a = 73 ...
[+] Trying a = 74 ...
[+] Trying a = 75 ...
[+] Trying a = 76 ...
[+] Trying a = 77 ...
[+] Key  FOUND: 2E-2E-2E-2E-2E-2E-2E-2E-2E-2E-2E-2E-2E-4D-16-0B
[+] Flag FOUND: hxp{th3y_pr0m153d_cr1t1c4l_but_0nly_g4v3_h1gh}
"""
# ----------------------------------------------------------------------------------------
