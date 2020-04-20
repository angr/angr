#!/usr/bin/python3

# A note from EDG:
#
# Hello angr community! We're insane, so we test angr on the real-est real binaries on the planet.
# How real? Well, so real we can't give them to you. Sorry!
# But rest assured, these are big, massive, complex binaries, with interrupts, weird hardware, DMA, etc, and no
# operating system to make things easier.
#
# If these tests break, contact @subwire (or, likely, he will find you)

from common import bin_priv_location, slow_test
import os
import angr


def load_econet():
    b = os.path.join(bin_priv_location, "firmware_party", "rheem_econet", "RH-WIFI-02-01-05.bin")
    p = angr.Project(b, main_opts={'base_addr': 0x1f000000, 'arch': 'ARMCortexM', 'backend': 'blob', 'entry_point': 0x1f0051b9})
    return p


def load_mycarelink():
    b = os.path.join(bin_priv_location, "firmware_party", "mycarelink", "mycarelink-from_app.bin")
    p = angr.Project(b, main_opts={'base_addr': 0x08044000,
                                   'arch': 'ARMCortexM',
                                   'backend': 'blob',
                                   'entry_point': 0x08049509})
    return p


def load_omnipod():
    b = os.path.join(bin_priv_location, "firmware_party", "omnipod_pdm", "flash.bin")
    p = angr.Project(b, main_opts={'base_addr': 0xc8000000, 'arch': 'ARMEL', 'backend': 'blob', 'entry_point': 0xc8000000})
    return p


def load_controllogix():
    b = os.path.join(bin_priv_location, "firmware_party", "ab_controllogix", "PN-337140.bin")
    p = angr.Project(b, main_opts={'base_addr': 0x100000, 'arch': 'ARMEL', 'backend': 'blob', 'entry_point': 0x100000})
    return p


def cfg_it(p):
    cfg = p.analyses.CFGFast(function_prologues=True,
                             resolve_indirect_jumps=True,
                             force_complete_scan=False,
                             show_progressbar=True,
                             normalize=True,
                             detect_tail_calls=True,
                             cross_references=True)
    cca = p.analyses.CompleteCallingConventions(recover_variables=True, force=True)
    return cfg, cca

@slow_test
def test_econet_cfg():
    """
    Econet CFG smoketest
    :return:
    """
    p = load_econet()
    _ = cfg_it(p)


@slow_test
def test_controllogix_cfg():
    """
    ControlLogix CFG smoketest
    :return:
    """
    p = load_controllogix()
    _ = cfg_it(p)


@slow_test
def test_omnipod_cfg():
    """
    MyCareLink CFG smoketest
    :return:
    """
    p = load_omnipod()
    _ = cfg_it(p)

@slow_test
def test_mycarelink_cfg():
    p = load_mycarelink()
    _ = cfg_it(p)

if __name__ == '__main__':
    test_mycarelink_cfg()
    test_controllogix_cfg()
    test_econet_cfg()
    test_omnipod_cfg()
