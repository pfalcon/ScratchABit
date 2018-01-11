loaders = ["elf"]

cpus = {
#"arm_32_thumb": "arm_thumb",  # Warning: this supports only Thumb, not Thumb2
"arm_32_thumb": "arm_32_thumb_capstone",
"arm_32_arm": "arm_32_arm_capstone",
"x86_32": "x86_32_pymsasid",
"x86_64": "x86_64_pymsasid",
"xtensa_32": "xtensa",
}
