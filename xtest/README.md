HOWTO build and run the xtest Test Suite
========================================

Updated: Mar 23, 2018.

Build instructions
==================

The xtest Test Suite is a REE client application using the GlobalPlatform
Client API. It is built using buildroot. Please refer to the HOWTO-ree readme
file for general instructions on how to build REE side components.

1. To enable the standard set of xtest test cases run `make menuconfig` from
the buildroot directory and check the 'xtest' option under
'External Options ---> MIPS-TEE packages'.

2. Build the REE client side xtest application and update the rootfs following
the instructions in HOWTO-ree.

```
    cd ree/buildroot
    # build and update rootfs
    make xtest-rebuild && make
```

3. Build the TEE xtest project following the instructions in HOWTO-tee.  The
Trusted Applications needed for the xtest framework are included in the
tee/mips-lk project on the TEE side.

```
    cd tee/mips-lk
    ./lk/scripts/do-l4re-mips-virt -p mips-ree-xtest
```


Building the extended GlobalPlatform Compliance Test Suite
==========================================================

The extended GlobalPlatform Compliance Test Suite is proprietary. It can be
purchased from www.globalplatform.org. The instructions below have been tested
with GP Compliance Test Suite version:

- TEE_Initial_Configuration-Test_Suite_v2_0_0-2016_05_25.

1. Set the $TEST_SUITE_DIR environment variable to the path of the GP
Compliance Test Suite:
```
    export TEST_SUITE_DIR=<path/to/GP_Compliance_Test_Suite>
```

2. From the buildroot directory, run make menuconfig and select the xtest and
xtest_gp options under 'External Options ---> MIPS-TEE packages'.

3. Re-build the REE side xtest and rootfs as usual. As part of the make process
a script will install the necessary GP Compliance Test Suite Trusted
Applications in 'tee/mips-lk/app/xtest' and will generate the necessary mips-lk
build files.

4. Next build the TEE mips-lk xtest project as usual.


Running the xtest test suite
============================

To run the full set of xtest test cases, simply run `xtest`.  If you want to
run just a subset of test cases, you can do so by adding a subset prefix, for
example:

- `xtest _90` for Crypto API test cases
- `xtest _10 _11` for standard test cases
- `xtest _70 _71` for Client API test cases

xtest Test Suite contents:
==========================
- test cases 10xx: basic test cases imported from OPTEE
- test cases 11xx and 12xx: custom internal test cases
- test cases 801xx and 807xx: custom internal Property API test cases
- test cases 70xxx and 71xxx: GP Compliance Client API test cases
- test cases 75xxx: GP Compliance Data Storage API test cases
- test cases 80xxx: GP Compliance Trusted Core Framework test cases
- test cases 85xxx: GP Compliance Time and Arithmetic API test cases
- test cases 90xxx: GP Compliance Crypto API test cases
