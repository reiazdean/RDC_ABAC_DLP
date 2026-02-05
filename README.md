This project is licensed under the Apache 2.0 open-source license and a commercial license
for enterprises wishing to deploy. See the License folder.

This project endeavors to protect sensitive documents from improper sharing.
It does so by enforcing mandatory access control onto documents that involve
multi-level and multi-category access control via attributes defined within the
enterprises Microsoft Active Directory infrastructure.
In doing so, the project is targeted towards just the Microsoft ecosystem within an
Enterprise.

This project protects digital documents authored with MS-Office or LibreOffice or
other document editing software with cryptographic technologies involving AES, RSA,
ECDSA and post quantum ready algorithms, Kyber and Dilithium.

You may clone this public repo like:
git clone --recurse-submodules git@github.com:reiazdean/RDC_ABAC_DLP.git

When cloned, depending projects for Crystals Kyber, Crystals Dilithium and OpenSSL
will also be cloned as sub-projects.

You must first build OpenSSL as follows.
1.	Download Perl installer from https://strawberryperl.com/
2.      Install Strawberry Perl.
3.	Download NASM installer from https://www.nasm.us/pub/nasm/releasebuilds/3.01rc9/win64/
4.      Install NASM.
5.	Open a Microsoft Visual Studio x64 Native Command Prompt
6.	cd [YourRepoPath]\RDC_ABAC_DLP\openssl
7.	perl Configure VC-WIN64A no-shared no-module no-tests
8.	nmake

Next, you will use the Visual Studio IDE to build the remainder of the project components.
1.	Launch Visual Studio.
2.	Open the DLPSolution.sln solution within the RDC_ABAC_DLP repo.
3.	Target the Release build.
4.	Right click the Dilithium project and “Build” the static library for Crystals Dilithium.
5.	Right click the Kyber project and “Build” the static library for Crystals Kyber.
6.	Right click the DLP_Service and “Build” the application service.
7.	Right click the DLP_Client and “Build” the application client.

Note. You may build Debug versions of the DLP_Service and DLP_Client applications. However Kyber
      and Dilithium must be Release builds.
      All, Release and Debug builds must target 64 bit targets.
