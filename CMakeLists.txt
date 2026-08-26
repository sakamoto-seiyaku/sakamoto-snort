cmake_minimum_required(VERSION 3.18)

project(sakamoto_snort_workspace LANGUAGES NONE)

# The former C++ sucre-snort daemon, its host model, and its NDK/APK staging
# target were deliberately removed.  Product packet code resumes only when
# the VPP-native C mainline exists; the C/VPP POCs remain evidence inputs and
# are built by their own scoped scripts, not by this repository root.
add_custom_target(
  sakamoto-vpp-mainline-pending
  COMMAND "${CMAKE_COMMAND}" -E echo
          "C/VPP product mainline is not implemented; no Snort C++ build target exists."
  VERBATIM
)

message(STATUS "Snort C++ implementation removed; see ADR-0008 and the Android/VPP handoff.")
