/*
 * Copyright 2013 The Native Client Authors.  All rights reserved.
 * Use of this source code is governed by a BSD-style license that can
 * be found in the LICENSE file.
 */

// DO NOT EDIT: GENERATED CODE

#ifndef NACL_TRUSTED_BUT_NOT_TCB
#error This file is not meant for use in the TCB
#endif


#include "gtest/gtest.h"
#include "native_client/src/trusted/validator_arm/actual_vs_baseline.h"
#include "native_client/src/trusted/validator_arm/baseline_vs_baseline.h"
#include "native_client/src/trusted/validator_arm/baseline_classes.h"
#include "native_client/src/trusted/validator_arm/inst_classes_testers.h"
#include "native_client/src/trusted/validator_arm/arm_helpers.h"
#include "native_client/src/trusted/validator_arm/gen/arm32_decode_named_bases.h"

using nacl_arm_dec::Instruction;
using nacl_arm_dec::ClassDecoder;
using nacl_arm_dec::Register;
using nacl_arm_dec::RegisterList;

namespace nacl_arm_test {

// The following classes are derived class decoder testers that
// add row pattern constraints and decoder restrictions to each tester.
// This is done so that it can be used to make sure that the
// corresponding pattern is not tested for cases that would be excluded
//  due to row checks, or restrictions specified by the row restrictions.


// op(23:20)=1000 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       actual: Actual_STREXB_cccc00011100nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREX_cccc00011000nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011000nnnndddd11111001tttt,
//       rule: STREX,
//       safety: [Pc in {Rd, Rt, Rn} => UNPREDICTABLE,
//         Rd in {Rn, Rt} => UNPREDICTABLE],
//       uses: {Rn, Rt}}
class STREX_cccc00011000nnnndddd11111001tttt_case_0TesterCase0
    : public Arm32DecoderTester {
 public:
  STREX_cccc00011000nnnndddd11111001tttt_case_0TesterCase0(const NamedClassDecoder& decoder)
    : Arm32DecoderTester(decoder) {}
  virtual bool PassesParsePreconditions(
      nacl_arm_dec::Instruction inst,
      const NamedClassDecoder& decoder);
  virtual bool ApplySanityChecks(nacl_arm_dec::Instruction inst,
                                 const NamedClassDecoder& decoder);
};

bool STREX_cccc00011000nnnndddd11111001tttt_case_0TesterCase0
::PassesParsePreconditions(
     nacl_arm_dec::Instruction inst,
     const NamedClassDecoder& decoder) {

  // Check that row patterns apply to pattern being checked.'
  // op(23:20)=~1000
  if ((inst.Bits() & 0x00F00000)  !=
          0x00800000) return false;
  // $pattern(31:0)=~xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
  if ((inst.Bits() & 0x00000F00)  !=
          0x00000F00) return false;

  // if cond(31:28)=1111, don't test instruction.
  if ((inst.Bits() & 0xF0000000) == 0xF0000000) return false;

  // Check other preconditions defined for the base decoder.
  return Arm32DecoderTester::
      PassesParsePreconditions(inst, decoder);
}

bool STREX_cccc00011000nnnndddd11111001tttt_case_0TesterCase0
::ApplySanityChecks(nacl_arm_dec::Instruction inst,
                    const NamedClassDecoder& decoder) {
  NC_PRECOND(Arm32DecoderTester::
               ApplySanityChecks(inst, decoder));

  // safety: Pc in {Rd, Rt, Rn} => UNPREDICTABLE
  EXPECT_TRUE(!((((15) == (((inst.Bits() & 0x0000F000) >> 12)))) ||
       (((15) == ((inst.Bits() & 0x0000000F)))) ||
       (((15) == (((inst.Bits() & 0x000F0000) >> 16))))));

  // safety: Rd in {Rn, Rt} => UNPREDICTABLE
  EXPECT_TRUE(!((((((inst.Bits() & 0x0000F000) >> 12)) == (((inst.Bits() & 0x000F0000) >> 16)))) ||
       (((((inst.Bits() & 0x0000F000) >> 12)) == ((inst.Bits() & 0x0000000F))))));

  // defs: {Rd};
  EXPECT_TRUE(decoder.defs(inst).IsSame(RegisterList().
   Add(Register(((inst.Bits() & 0x0000F000) >> 12)))));

  return true;
}

// op(23:20)=1001 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       actual: Actual_LDREXB_cccc00011101nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: LDREX_cccc00011001nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011001nnnntttt111110011111,
//       rule: LDREX,
//       safety: [Pc in {Rt, Rn} => UNPREDICTABLE],
//       uses: {Rn}}
class LDREX_cccc00011001nnnntttt111110011111_case_0TesterCase1
    : public Arm32DecoderTester {
 public:
  LDREX_cccc00011001nnnntttt111110011111_case_0TesterCase1(const NamedClassDecoder& decoder)
    : Arm32DecoderTester(decoder) {}
  virtual bool PassesParsePreconditions(
      nacl_arm_dec::Instruction inst,
      const NamedClassDecoder& decoder);
  virtual bool ApplySanityChecks(nacl_arm_dec::Instruction inst,
                                 const NamedClassDecoder& decoder);
};

bool LDREX_cccc00011001nnnntttt111110011111_case_0TesterCase1
::PassesParsePreconditions(
     nacl_arm_dec::Instruction inst,
     const NamedClassDecoder& decoder) {

  // Check that row patterns apply to pattern being checked.'
  // op(23:20)=~1001
  if ((inst.Bits() & 0x00F00000)  !=
          0x00900000) return false;
  // $pattern(31:0)=~xxxxxxxxxxxxxxxxxxxx1111xxxx1111
  if ((inst.Bits() & 0x00000F0F)  !=
          0x00000F0F) return false;

  // if cond(31:28)=1111, don't test instruction.
  if ((inst.Bits() & 0xF0000000) == 0xF0000000) return false;

  // Check other preconditions defined for the base decoder.
  return Arm32DecoderTester::
      PassesParsePreconditions(inst, decoder);
}

bool LDREX_cccc00011001nnnntttt111110011111_case_0TesterCase1
::ApplySanityChecks(nacl_arm_dec::Instruction inst,
                    const NamedClassDecoder& decoder) {
  NC_PRECOND(Arm32DecoderTester::
               ApplySanityChecks(inst, decoder));

  // safety: Pc in {Rt, Rn} => UNPREDICTABLE
  EXPECT_TRUE(!((((15) == (((inst.Bits() & 0x0000F000) >> 12)))) ||
       (((15) == (((inst.Bits() & 0x000F0000) >> 16))))));

  // defs: {Rt};
  EXPECT_TRUE(decoder.defs(inst).IsSame(RegisterList().
   Add(Register(((inst.Bits() & 0x0000F000) >> 12)))));

  return true;
}

// op(23:20)=1010 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Lr: 14,
//       Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       Rt2: Rt + 1,
//       actual: Actual_STREXD_cccc00011010nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREXD_cccc00011010nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011010nnnndddd11111001tttt,
//       rule: STREXD,
//       safety: [Pc in {Rd, Rn} ||
//            Rt(0)=1 ||
//            Rt  ==
//               Lr => UNPREDICTABLE,
//         Rd in {Rn, Rt, Rt2} => UNPREDICTABLE],
//       uses: {Rn, Rt, Rt2}}
class STREXD_cccc00011010nnnndddd11111001tttt_case_0TesterCase2
    : public Arm32DecoderTester {
 public:
  STREXD_cccc00011010nnnndddd11111001tttt_case_0TesterCase2(const NamedClassDecoder& decoder)
    : Arm32DecoderTester(decoder) {}
  virtual bool PassesParsePreconditions(
      nacl_arm_dec::Instruction inst,
      const NamedClassDecoder& decoder);
  virtual bool ApplySanityChecks(nacl_arm_dec::Instruction inst,
                                 const NamedClassDecoder& decoder);
};

bool STREXD_cccc00011010nnnndddd11111001tttt_case_0TesterCase2
::PassesParsePreconditions(
     nacl_arm_dec::Instruction inst,
     const NamedClassDecoder& decoder) {

  // Check that row patterns apply to pattern being checked.'
  // op(23:20)=~1010
  if ((inst.Bits() & 0x00F00000)  !=
          0x00A00000) return false;
  // $pattern(31:0)=~xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
  if ((inst.Bits() & 0x00000F00)  !=
          0x00000F00) return false;

  // if cond(31:28)=1111, don't test instruction.
  if ((inst.Bits() & 0xF0000000) == 0xF0000000) return false;

  // Check other preconditions defined for the base decoder.
  return Arm32DecoderTester::
      PassesParsePreconditions(inst, decoder);
}

bool STREXD_cccc00011010nnnndddd11111001tttt_case_0TesterCase2
::ApplySanityChecks(nacl_arm_dec::Instruction inst,
                    const NamedClassDecoder& decoder) {
  NC_PRECOND(Arm32DecoderTester::
               ApplySanityChecks(inst, decoder));

  // safety: Pc in {Rd, Rn} ||
  //       Rt(0)=1 ||
  //       Rt  ==
  //          Lr => UNPREDICTABLE
  EXPECT_TRUE(!(((((15) == (((inst.Bits() & 0x0000F000) >> 12)))) ||
       (((15) == (((inst.Bits() & 0x000F0000) >> 16))))) ||
       (((inst.Bits() & 0x0000000F) & 0x00000001)  ==
          0x00000001) ||
       ((((inst.Bits() & 0x0000000F)) == (14)))));

  // safety: Rd in {Rn, Rt, Rt2} => UNPREDICTABLE
  EXPECT_TRUE(!((((((inst.Bits() & 0x0000F000) >> 12)) == (((inst.Bits() & 0x000F0000) >> 16)))) ||
       (((((inst.Bits() & 0x0000F000) >> 12)) == ((inst.Bits() & 0x0000000F)))) ||
       (((((inst.Bits() & 0x0000F000) >> 12)) == ((inst.Bits() & 0x0000000F) + 1)))));

  // defs: {Rd};
  EXPECT_TRUE(decoder.defs(inst).IsSame(RegisterList().
   Add(Register(((inst.Bits() & 0x0000F000) >> 12)))));

  return true;
}

// op(23:20)=1011 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Lr: 14,
//       Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       Rt2: Rt + 1,
//       actual: Actual_LDREXD_cccc00011011nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: LDREXD_cccc00011011nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt, Rt2},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011011nnnntttt111110011111,
//       rule: LDREXD,
//       safety: [Rt(0)=1 ||
//            Rt  ==
//               Lr ||
//            Rn  ==
//               Pc => UNPREDICTABLE],
//       uses: {Rn}}
class LDREXD_cccc00011011nnnntttt111110011111_case_0TesterCase3
    : public Arm32DecoderTester {
 public:
  LDREXD_cccc00011011nnnntttt111110011111_case_0TesterCase3(const NamedClassDecoder& decoder)
    : Arm32DecoderTester(decoder) {}
  virtual bool PassesParsePreconditions(
      nacl_arm_dec::Instruction inst,
      const NamedClassDecoder& decoder);
  virtual bool ApplySanityChecks(nacl_arm_dec::Instruction inst,
                                 const NamedClassDecoder& decoder);
};

bool LDREXD_cccc00011011nnnntttt111110011111_case_0TesterCase3
::PassesParsePreconditions(
     nacl_arm_dec::Instruction inst,
     const NamedClassDecoder& decoder) {

  // Check that row patterns apply to pattern being checked.'
  // op(23:20)=~1011
  if ((inst.Bits() & 0x00F00000)  !=
          0x00B00000) return false;
  // $pattern(31:0)=~xxxxxxxxxxxxxxxxxxxx1111xxxx1111
  if ((inst.Bits() & 0x00000F0F)  !=
          0x00000F0F) return false;

  // if cond(31:28)=1111, don't test instruction.
  if ((inst.Bits() & 0xF0000000) == 0xF0000000) return false;

  // Check other preconditions defined for the base decoder.
  return Arm32DecoderTester::
      PassesParsePreconditions(inst, decoder);
}

bool LDREXD_cccc00011011nnnntttt111110011111_case_0TesterCase3
::ApplySanityChecks(nacl_arm_dec::Instruction inst,
                    const NamedClassDecoder& decoder) {
  NC_PRECOND(Arm32DecoderTester::
               ApplySanityChecks(inst, decoder));

  // safety: Rt(0)=1 ||
  //       Rt  ==
  //          Lr ||
  //       Rn  ==
  //          Pc => UNPREDICTABLE
  EXPECT_TRUE(!(((((inst.Bits() & 0x0000F000) >> 12) & 0x00000001)  ==
          0x00000001) ||
       (((((inst.Bits() & 0x0000F000) >> 12)) == (14))) ||
       (((((inst.Bits() & 0x000F0000) >> 16)) == (15)))));

  // defs: {Rt, Rt2};
  EXPECT_TRUE(decoder.defs(inst).IsSame(RegisterList().
   Add(Register(((inst.Bits() & 0x0000F000) >> 12))).
   Add(Register(((inst.Bits() & 0x0000F000) >> 12) + 1))));

  return true;
}

// op(23:20)=1100 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       actual: Actual_STREXB_cccc00011100nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREXB_cccc00011100nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011100nnnndddd11111001tttt,
//       rule: STREXB,
//       safety: [Pc in {Rd, Rt, Rn} => UNPREDICTABLE,
//         Rd in {Rn, Rt} => UNPREDICTABLE],
//       uses: {Rn, Rt}}
class STREXB_cccc00011100nnnndddd11111001tttt_case_0TesterCase4
    : public Arm32DecoderTester {
 public:
  STREXB_cccc00011100nnnndddd11111001tttt_case_0TesterCase4(const NamedClassDecoder& decoder)
    : Arm32DecoderTester(decoder) {}
  virtual bool PassesParsePreconditions(
      nacl_arm_dec::Instruction inst,
      const NamedClassDecoder& decoder);
  virtual bool ApplySanityChecks(nacl_arm_dec::Instruction inst,
                                 const NamedClassDecoder& decoder);
};

bool STREXB_cccc00011100nnnndddd11111001tttt_case_0TesterCase4
::PassesParsePreconditions(
     nacl_arm_dec::Instruction inst,
     const NamedClassDecoder& decoder) {

  // Check that row patterns apply to pattern being checked.'
  // op(23:20)=~1100
  if ((inst.Bits() & 0x00F00000)  !=
          0x00C00000) return false;
  // $pattern(31:0)=~xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
  if ((inst.Bits() & 0x00000F00)  !=
          0x00000F00) return false;

  // if cond(31:28)=1111, don't test instruction.
  if ((inst.Bits() & 0xF0000000) == 0xF0000000) return false;

  // Check other preconditions defined for the base decoder.
  return Arm32DecoderTester::
      PassesParsePreconditions(inst, decoder);
}

bool STREXB_cccc00011100nnnndddd11111001tttt_case_0TesterCase4
::ApplySanityChecks(nacl_arm_dec::Instruction inst,
                    const NamedClassDecoder& decoder) {
  NC_PRECOND(Arm32DecoderTester::
               ApplySanityChecks(inst, decoder));

  // safety: Pc in {Rd, Rt, Rn} => UNPREDICTABLE
  EXPECT_TRUE(!((((15) == (((inst.Bits() & 0x0000F000) >> 12)))) ||
       (((15) == ((inst.Bits() & 0x0000000F)))) ||
       (((15) == (((inst.Bits() & 0x000F0000) >> 16))))));

  // safety: Rd in {Rn, Rt} => UNPREDICTABLE
  EXPECT_TRUE(!((((((inst.Bits() & 0x0000F000) >> 12)) == (((inst.Bits() & 0x000F0000) >> 16)))) ||
       (((((inst.Bits() & 0x0000F000) >> 12)) == ((inst.Bits() & 0x0000000F))))));

  // defs: {Rd};
  EXPECT_TRUE(decoder.defs(inst).IsSame(RegisterList().
   Add(Register(((inst.Bits() & 0x0000F000) >> 12)))));

  return true;
}

// op(23:20)=1101 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       actual: Actual_LDREXB_cccc00011101nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: LDREXB_cccc00011101nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011101nnnntttt111110011111,
//       rule: LDREXB,
//       safety: [Pc in {Rt, Rn} => UNPREDICTABLE],
//       uses: {Rn}}
class LDREXB_cccc00011101nnnntttt111110011111_case_0TesterCase5
    : public Arm32DecoderTester {
 public:
  LDREXB_cccc00011101nnnntttt111110011111_case_0TesterCase5(const NamedClassDecoder& decoder)
    : Arm32DecoderTester(decoder) {}
  virtual bool PassesParsePreconditions(
      nacl_arm_dec::Instruction inst,
      const NamedClassDecoder& decoder);
  virtual bool ApplySanityChecks(nacl_arm_dec::Instruction inst,
                                 const NamedClassDecoder& decoder);
};

bool LDREXB_cccc00011101nnnntttt111110011111_case_0TesterCase5
::PassesParsePreconditions(
     nacl_arm_dec::Instruction inst,
     const NamedClassDecoder& decoder) {

  // Check that row patterns apply to pattern being checked.'
  // op(23:20)=~1101
  if ((inst.Bits() & 0x00F00000)  !=
          0x00D00000) return false;
  // $pattern(31:0)=~xxxxxxxxxxxxxxxxxxxx1111xxxx1111
  if ((inst.Bits() & 0x00000F0F)  !=
          0x00000F0F) return false;

  // if cond(31:28)=1111, don't test instruction.
  if ((inst.Bits() & 0xF0000000) == 0xF0000000) return false;

  // Check other preconditions defined for the base decoder.
  return Arm32DecoderTester::
      PassesParsePreconditions(inst, decoder);
}

bool LDREXB_cccc00011101nnnntttt111110011111_case_0TesterCase5
::ApplySanityChecks(nacl_arm_dec::Instruction inst,
                    const NamedClassDecoder& decoder) {
  NC_PRECOND(Arm32DecoderTester::
               ApplySanityChecks(inst, decoder));

  // safety: Pc in {Rt, Rn} => UNPREDICTABLE
  EXPECT_TRUE(!((((15) == (((inst.Bits() & 0x0000F000) >> 12)))) ||
       (((15) == (((inst.Bits() & 0x000F0000) >> 16))))));

  // defs: {Rt};
  EXPECT_TRUE(decoder.defs(inst).IsSame(RegisterList().
   Add(Register(((inst.Bits() & 0x0000F000) >> 12)))));

  return true;
}

// op(23:20)=1110 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       actual: Actual_STREXB_cccc00011100nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREXH_cccc00011110nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011110nnnndddd11111001tttt,
//       rule: STREXH,
//       safety: [Pc in {Rd, Rt, Rn} => UNPREDICTABLE,
//         Rd in {Rn, Rt} => UNPREDICTABLE],
//       uses: {Rn, Rt}}
class STREXH_cccc00011110nnnndddd11111001tttt_case_0TesterCase6
    : public Arm32DecoderTester {
 public:
  STREXH_cccc00011110nnnndddd11111001tttt_case_0TesterCase6(const NamedClassDecoder& decoder)
    : Arm32DecoderTester(decoder) {}
  virtual bool PassesParsePreconditions(
      nacl_arm_dec::Instruction inst,
      const NamedClassDecoder& decoder);
  virtual bool ApplySanityChecks(nacl_arm_dec::Instruction inst,
                                 const NamedClassDecoder& decoder);
};

bool STREXH_cccc00011110nnnndddd11111001tttt_case_0TesterCase6
::PassesParsePreconditions(
     nacl_arm_dec::Instruction inst,
     const NamedClassDecoder& decoder) {

  // Check that row patterns apply to pattern being checked.'
  // op(23:20)=~1110
  if ((inst.Bits() & 0x00F00000)  !=
          0x00E00000) return false;
  // $pattern(31:0)=~xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
  if ((inst.Bits() & 0x00000F00)  !=
          0x00000F00) return false;

  // if cond(31:28)=1111, don't test instruction.
  if ((inst.Bits() & 0xF0000000) == 0xF0000000) return false;

  // Check other preconditions defined for the base decoder.
  return Arm32DecoderTester::
      PassesParsePreconditions(inst, decoder);
}

bool STREXH_cccc00011110nnnndddd11111001tttt_case_0TesterCase6
::ApplySanityChecks(nacl_arm_dec::Instruction inst,
                    const NamedClassDecoder& decoder) {
  NC_PRECOND(Arm32DecoderTester::
               ApplySanityChecks(inst, decoder));

  // safety: Pc in {Rd, Rt, Rn} => UNPREDICTABLE
  EXPECT_TRUE(!((((15) == (((inst.Bits() & 0x0000F000) >> 12)))) ||
       (((15) == ((inst.Bits() & 0x0000000F)))) ||
       (((15) == (((inst.Bits() & 0x000F0000) >> 16))))));

  // safety: Rd in {Rn, Rt} => UNPREDICTABLE
  EXPECT_TRUE(!((((((inst.Bits() & 0x0000F000) >> 12)) == (((inst.Bits() & 0x000F0000) >> 16)))) ||
       (((((inst.Bits() & 0x0000F000) >> 12)) == ((inst.Bits() & 0x0000000F))))));

  // defs: {Rd};
  EXPECT_TRUE(decoder.defs(inst).IsSame(RegisterList().
   Add(Register(((inst.Bits() & 0x0000F000) >> 12)))));

  return true;
}

// op(23:20)=1111 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       actual: Actual_LDREXB_cccc00011101nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: STREXH_cccc00011111nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011111nnnntttt111110011111,
//       rule: STREXH,
//       safety: [Pc in {Rt, Rn} => UNPREDICTABLE],
//       uses: {Rn}}
class STREXH_cccc00011111nnnntttt111110011111_case_0TesterCase7
    : public Arm32DecoderTester {
 public:
  STREXH_cccc00011111nnnntttt111110011111_case_0TesterCase7(const NamedClassDecoder& decoder)
    : Arm32DecoderTester(decoder) {}
  virtual bool PassesParsePreconditions(
      nacl_arm_dec::Instruction inst,
      const NamedClassDecoder& decoder);
  virtual bool ApplySanityChecks(nacl_arm_dec::Instruction inst,
                                 const NamedClassDecoder& decoder);
};

bool STREXH_cccc00011111nnnntttt111110011111_case_0TesterCase7
::PassesParsePreconditions(
     nacl_arm_dec::Instruction inst,
     const NamedClassDecoder& decoder) {

  // Check that row patterns apply to pattern being checked.'
  // op(23:20)=~1111
  if ((inst.Bits() & 0x00F00000)  !=
          0x00F00000) return false;
  // $pattern(31:0)=~xxxxxxxxxxxxxxxxxxxx1111xxxx1111
  if ((inst.Bits() & 0x00000F0F)  !=
          0x00000F0F) return false;

  // if cond(31:28)=1111, don't test instruction.
  if ((inst.Bits() & 0xF0000000) == 0xF0000000) return false;

  // Check other preconditions defined for the base decoder.
  return Arm32DecoderTester::
      PassesParsePreconditions(inst, decoder);
}

bool STREXH_cccc00011111nnnntttt111110011111_case_0TesterCase7
::ApplySanityChecks(nacl_arm_dec::Instruction inst,
                    const NamedClassDecoder& decoder) {
  NC_PRECOND(Arm32DecoderTester::
               ApplySanityChecks(inst, decoder));

  // safety: Pc in {Rt, Rn} => UNPREDICTABLE
  EXPECT_TRUE(!((((15) == (((inst.Bits() & 0x0000F000) >> 12)))) ||
       (((15) == (((inst.Bits() & 0x000F0000) >> 16))))));

  // defs: {Rt};
  EXPECT_TRUE(decoder.defs(inst).IsSame(RegisterList().
   Add(Register(((inst.Bits() & 0x0000F000) >> 12)))));

  return true;
}

// op(23:20)=0x00 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx0000xxxxxxxx
//    = {actual: Deprecated,
//       baseline: Deprecated,
//       constraints: ,
//       pattern: cccc00010b00nnnntttt00001001tttt,
//       rule: SWP_SWPB}
class DeprecatedTesterCase8
    : public UnsafeCondDecoderTester {
 public:
  DeprecatedTesterCase8(const NamedClassDecoder& decoder)
    : UnsafeCondDecoderTester(decoder) {}
  virtual bool PassesParsePreconditions(
      nacl_arm_dec::Instruction inst,
      const NamedClassDecoder& decoder);
};

bool DeprecatedTesterCase8
::PassesParsePreconditions(
     nacl_arm_dec::Instruction inst,
     const NamedClassDecoder& decoder) {

  // Check that row patterns apply to pattern being checked.'
  // op(23:20)=~0x00
  if ((inst.Bits() & 0x00B00000)  !=
          0x00000000) return false;
  // $pattern(31:0)=~xxxxxxxxxxxxxxxxxxxx0000xxxxxxxx
  if ((inst.Bits() & 0x00000F00)  !=
          0x00000000) return false;

  // if cond(31:28)=1111, don't test instruction.
  if ((inst.Bits() & 0xF0000000) == 0xF0000000) return false;

  // Check other preconditions defined for the base decoder.
  return UnsafeCondDecoderTester::
      PassesParsePreconditions(inst, decoder);
}

// The following are derived class decoder testers for decoder actions
// associated with a pattern of an action. These derived classes introduce
// a default constructor that automatically initializes the expected decoder
// to the corresponding instance in the generated DecoderState.

// op(23:20)=1000 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       actual: Actual_STREXB_cccc00011100nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREX_cccc00011000nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011000nnnndddd11111001tttt,
//       rule: STREX,
//       safety: [Pc in {Rd, Rt, Rn} => UNPREDICTABLE,
//         Rd in {Rn, Rt} => UNPREDICTABLE],
//       uses: {Rn, Rt}}
class STREX_cccc00011000nnnndddd11111001tttt_case_0Tester_Case0
    : public STREX_cccc00011000nnnndddd11111001tttt_case_0TesterCase0 {
 public:
  STREX_cccc00011000nnnndddd11111001tttt_case_0Tester_Case0()
    : STREX_cccc00011000nnnndddd11111001tttt_case_0TesterCase0(
      state_.STREX_cccc00011000nnnndddd11111001tttt_case_0_STREX_instance_)
  {}
};

// op(23:20)=1001 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       actual: Actual_LDREXB_cccc00011101nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: LDREX_cccc00011001nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011001nnnntttt111110011111,
//       rule: LDREX,
//       safety: [Pc in {Rt, Rn} => UNPREDICTABLE],
//       uses: {Rn}}
class LDREX_cccc00011001nnnntttt111110011111_case_0Tester_Case1
    : public LDREX_cccc00011001nnnntttt111110011111_case_0TesterCase1 {
 public:
  LDREX_cccc00011001nnnntttt111110011111_case_0Tester_Case1()
    : LDREX_cccc00011001nnnntttt111110011111_case_0TesterCase1(
      state_.LDREX_cccc00011001nnnntttt111110011111_case_0_LDREX_instance_)
  {}
};

// op(23:20)=1010 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Lr: 14,
//       Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       Rt2: Rt + 1,
//       actual: Actual_STREXD_cccc00011010nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREXD_cccc00011010nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011010nnnndddd11111001tttt,
//       rule: STREXD,
//       safety: [Pc in {Rd, Rn} ||
//            Rt(0)=1 ||
//            Rt  ==
//               Lr => UNPREDICTABLE,
//         Rd in {Rn, Rt, Rt2} => UNPREDICTABLE],
//       uses: {Rn, Rt, Rt2}}
class STREXD_cccc00011010nnnndddd11111001tttt_case_0Tester_Case2
    : public STREXD_cccc00011010nnnndddd11111001tttt_case_0TesterCase2 {
 public:
  STREXD_cccc00011010nnnndddd11111001tttt_case_0Tester_Case2()
    : STREXD_cccc00011010nnnndddd11111001tttt_case_0TesterCase2(
      state_.STREXD_cccc00011010nnnndddd11111001tttt_case_0_STREXD_instance_)
  {}
};

// op(23:20)=1011 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Lr: 14,
//       Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       Rt2: Rt + 1,
//       actual: Actual_LDREXD_cccc00011011nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: LDREXD_cccc00011011nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt, Rt2},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011011nnnntttt111110011111,
//       rule: LDREXD,
//       safety: [Rt(0)=1 ||
//            Rt  ==
//               Lr ||
//            Rn  ==
//               Pc => UNPREDICTABLE],
//       uses: {Rn}}
class LDREXD_cccc00011011nnnntttt111110011111_case_0Tester_Case3
    : public LDREXD_cccc00011011nnnntttt111110011111_case_0TesterCase3 {
 public:
  LDREXD_cccc00011011nnnntttt111110011111_case_0Tester_Case3()
    : LDREXD_cccc00011011nnnntttt111110011111_case_0TesterCase3(
      state_.LDREXD_cccc00011011nnnntttt111110011111_case_0_LDREXD_instance_)
  {}
};

// op(23:20)=1100 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       actual: Actual_STREXB_cccc00011100nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREXB_cccc00011100nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011100nnnndddd11111001tttt,
//       rule: STREXB,
//       safety: [Pc in {Rd, Rt, Rn} => UNPREDICTABLE,
//         Rd in {Rn, Rt} => UNPREDICTABLE],
//       uses: {Rn, Rt}}
class STREXB_cccc00011100nnnndddd11111001tttt_case_0Tester_Case4
    : public STREXB_cccc00011100nnnndddd11111001tttt_case_0TesterCase4 {
 public:
  STREXB_cccc00011100nnnndddd11111001tttt_case_0Tester_Case4()
    : STREXB_cccc00011100nnnndddd11111001tttt_case_0TesterCase4(
      state_.STREXB_cccc00011100nnnndddd11111001tttt_case_0_STREXB_instance_)
  {}
};

// op(23:20)=1101 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       actual: Actual_LDREXB_cccc00011101nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: LDREXB_cccc00011101nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011101nnnntttt111110011111,
//       rule: LDREXB,
//       safety: [Pc in {Rt, Rn} => UNPREDICTABLE],
//       uses: {Rn}}
class LDREXB_cccc00011101nnnntttt111110011111_case_0Tester_Case5
    : public LDREXB_cccc00011101nnnntttt111110011111_case_0TesterCase5 {
 public:
  LDREXB_cccc00011101nnnntttt111110011111_case_0Tester_Case5()
    : LDREXB_cccc00011101nnnntttt111110011111_case_0TesterCase5(
      state_.LDREXB_cccc00011101nnnntttt111110011111_case_0_LDREXB_instance_)
  {}
};

// op(23:20)=1110 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       actual: Actual_STREXB_cccc00011100nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREXH_cccc00011110nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011110nnnndddd11111001tttt,
//       rule: STREXH,
//       safety: [Pc in {Rd, Rt, Rn} => UNPREDICTABLE,
//         Rd in {Rn, Rt} => UNPREDICTABLE],
//       uses: {Rn, Rt}}
class STREXH_cccc00011110nnnndddd11111001tttt_case_0Tester_Case6
    : public STREXH_cccc00011110nnnndddd11111001tttt_case_0TesterCase6 {
 public:
  STREXH_cccc00011110nnnndddd11111001tttt_case_0Tester_Case6()
    : STREXH_cccc00011110nnnndddd11111001tttt_case_0TesterCase6(
      state_.STREXH_cccc00011110nnnndddd11111001tttt_case_0_STREXH_instance_)
  {}
};

// op(23:20)=1111 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       actual: Actual_LDREXB_cccc00011101nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: STREXH_cccc00011111nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011111nnnntttt111110011111,
//       rule: STREXH,
//       safety: [Pc in {Rt, Rn} => UNPREDICTABLE],
//       uses: {Rn}}
class STREXH_cccc00011111nnnntttt111110011111_case_0Tester_Case7
    : public STREXH_cccc00011111nnnntttt111110011111_case_0TesterCase7 {
 public:
  STREXH_cccc00011111nnnntttt111110011111_case_0Tester_Case7()
    : STREXH_cccc00011111nnnntttt111110011111_case_0TesterCase7(
      state_.STREXH_cccc00011111nnnntttt111110011111_case_0_STREXH_instance_)
  {}
};

// op(23:20)=0x00 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx0000xxxxxxxx
//    = {actual: Deprecated,
//       baseline: Deprecated,
//       constraints: ,
//       pattern: cccc00010b00nnnntttt00001001tttt,
//       rule: SWP_SWPB}
class DeprecatedTester_Case8
    : public DeprecatedTesterCase8 {
 public:
  DeprecatedTester_Case8()
    : DeprecatedTesterCase8(
      state_.Deprecated_SWP_SWPB_instance_)
  {}
};

// Defines a gtest testing harness for tests.
class Arm32DecoderStateTests : public ::testing::Test {
 protected:
  Arm32DecoderStateTests() {}
};

// The following functions test each pattern specified in parse
// decoder tables.

// op(23:20)=1000 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       actual: Actual_STREXB_cccc00011100nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREX_cccc00011000nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011000nnnndddd11111001tttt,
//       rule: STREX,
//       safety: [Pc in {Rd, Rt, Rn} => UNPREDICTABLE,
//         Rd in {Rn, Rt} => UNPREDICTABLE],
//       uses: {Rn, Rt}}
TEST_F(Arm32DecoderStateTests,
       STREX_cccc00011000nnnndddd11111001tttt_case_0Tester_Case0_TestCase0) {
  STREX_cccc00011000nnnndddd11111001tttt_case_0Tester_Case0 baseline_tester;
  NamedActual_STREXB_cccc00011100nnnndddd11111001tttt_case_1_STREX actual;
  ActualVsBaselineTester a_vs_b_tester(actual, baseline_tester);
  a_vs_b_tester.Test("cccc00011000nnnndddd11111001tttt");
}

// op(23:20)=1001 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       actual: Actual_LDREXB_cccc00011101nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: LDREX_cccc00011001nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011001nnnntttt111110011111,
//       rule: LDREX,
//       safety: [Pc in {Rt, Rn} => UNPREDICTABLE],
//       uses: {Rn}}
TEST_F(Arm32DecoderStateTests,
       LDREX_cccc00011001nnnntttt111110011111_case_0Tester_Case1_TestCase1) {
  LDREX_cccc00011001nnnntttt111110011111_case_0Tester_Case1 baseline_tester;
  NamedActual_LDREXB_cccc00011101nnnntttt111110011111_case_1_LDREX actual;
  ActualVsBaselineTester a_vs_b_tester(actual, baseline_tester);
  a_vs_b_tester.Test("cccc00011001nnnntttt111110011111");
}

// op(23:20)=1010 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Lr: 14,
//       Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       Rt2: Rt + 1,
//       actual: Actual_STREXD_cccc00011010nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREXD_cccc00011010nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011010nnnndddd11111001tttt,
//       rule: STREXD,
//       safety: [Pc in {Rd, Rn} ||
//            Rt(0)=1 ||
//            Rt  ==
//               Lr => UNPREDICTABLE,
//         Rd in {Rn, Rt, Rt2} => UNPREDICTABLE],
//       uses: {Rn, Rt, Rt2}}
TEST_F(Arm32DecoderStateTests,
       STREXD_cccc00011010nnnndddd11111001tttt_case_0Tester_Case2_TestCase2) {
  STREXD_cccc00011010nnnndddd11111001tttt_case_0Tester_Case2 baseline_tester;
  NamedActual_STREXD_cccc00011010nnnndddd11111001tttt_case_1_STREXD actual;
  ActualVsBaselineTester a_vs_b_tester(actual, baseline_tester);
  a_vs_b_tester.Test("cccc00011010nnnndddd11111001tttt");
}

// op(23:20)=1011 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Lr: 14,
//       Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       Rt2: Rt + 1,
//       actual: Actual_LDREXD_cccc00011011nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: LDREXD_cccc00011011nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt, Rt2},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011011nnnntttt111110011111,
//       rule: LDREXD,
//       safety: [Rt(0)=1 ||
//            Rt  ==
//               Lr ||
//            Rn  ==
//               Pc => UNPREDICTABLE],
//       uses: {Rn}}
TEST_F(Arm32DecoderStateTests,
       LDREXD_cccc00011011nnnntttt111110011111_case_0Tester_Case3_TestCase3) {
  LDREXD_cccc00011011nnnntttt111110011111_case_0Tester_Case3 baseline_tester;
  NamedActual_LDREXD_cccc00011011nnnntttt111110011111_case_1_LDREXD actual;
  ActualVsBaselineTester a_vs_b_tester(actual, baseline_tester);
  a_vs_b_tester.Test("cccc00011011nnnntttt111110011111");
}

// op(23:20)=1100 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       actual: Actual_STREXB_cccc00011100nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREXB_cccc00011100nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011100nnnndddd11111001tttt,
//       rule: STREXB,
//       safety: [Pc in {Rd, Rt, Rn} => UNPREDICTABLE,
//         Rd in {Rn, Rt} => UNPREDICTABLE],
//       uses: {Rn, Rt}}
TEST_F(Arm32DecoderStateTests,
       STREXB_cccc00011100nnnndddd11111001tttt_case_0Tester_Case4_TestCase4) {
  STREXB_cccc00011100nnnndddd11111001tttt_case_0Tester_Case4 baseline_tester;
  NamedActual_STREXB_cccc00011100nnnndddd11111001tttt_case_1_STREXB actual;
  ActualVsBaselineTester a_vs_b_tester(actual, baseline_tester);
  a_vs_b_tester.Test("cccc00011100nnnndddd11111001tttt");
}

// op(23:20)=1101 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       actual: Actual_LDREXB_cccc00011101nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: LDREXB_cccc00011101nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011101nnnntttt111110011111,
//       rule: LDREXB,
//       safety: [Pc in {Rt, Rn} => UNPREDICTABLE],
//       uses: {Rn}}
TEST_F(Arm32DecoderStateTests,
       LDREXB_cccc00011101nnnntttt111110011111_case_0Tester_Case5_TestCase5) {
  LDREXB_cccc00011101nnnntttt111110011111_case_0Tester_Case5 baseline_tester;
  NamedActual_LDREXB_cccc00011101nnnntttt111110011111_case_1_LDREXB actual;
  ActualVsBaselineTester a_vs_b_tester(actual, baseline_tester);
  a_vs_b_tester.Test("cccc00011101nnnntttt111110011111");
}

// op(23:20)=1110 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxxxxxx
//    = {Pc: 15,
//       Rd: Rd(15:12),
//       Rn: Rn(19:16),
//       Rt: Rt(3:0),
//       actual: Actual_STREXB_cccc00011100nnnndddd11111001tttt_case_1,
//       base: Rn,
//       baseline: STREXH_cccc00011110nnnndddd11111001tttt_case_0,
//       constraints: ,
//       defs: {Rd},
//       fields: [Rn(19:16), Rd(15:12), Rt(3:0)],
//       pattern: cccc00011110nnnndddd11111001tttt,
//       rule: STREXH,
//       safety: [Pc in {Rd, Rt, Rn} => UNPREDICTABLE,
//         Rd in {Rn, Rt} => UNPREDICTABLE],
//       uses: {Rn, Rt}}
TEST_F(Arm32DecoderStateTests,
       STREXH_cccc00011110nnnndddd11111001tttt_case_0Tester_Case6_TestCase6) {
  STREXH_cccc00011110nnnndddd11111001tttt_case_0Tester_Case6 baseline_tester;
  NamedActual_STREXB_cccc00011100nnnndddd11111001tttt_case_1_STREXH actual;
  ActualVsBaselineTester a_vs_b_tester(actual, baseline_tester);
  a_vs_b_tester.Test("cccc00011110nnnndddd11111001tttt");
}

// op(23:20)=1111 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx1111xxxx1111
//    = {Pc: 15,
//       Rn: Rn(19:16),
//       Rt: Rt(15:12),
//       actual: Actual_LDREXB_cccc00011101nnnntttt111110011111_case_1,
//       base: Rn,
//       baseline: STREXH_cccc00011111nnnntttt111110011111_case_0,
//       constraints: ,
//       defs: {Rt},
//       fields: [Rn(19:16), Rt(15:12)],
//       pattern: cccc00011111nnnntttt111110011111,
//       rule: STREXH,
//       safety: [Pc in {Rt, Rn} => UNPREDICTABLE],
//       uses: {Rn}}
TEST_F(Arm32DecoderStateTests,
       STREXH_cccc00011111nnnntttt111110011111_case_0Tester_Case7_TestCase7) {
  STREXH_cccc00011111nnnntttt111110011111_case_0Tester_Case7 baseline_tester;
  NamedActual_LDREXB_cccc00011101nnnntttt111110011111_case_1_STREXH actual;
  ActualVsBaselineTester a_vs_b_tester(actual, baseline_tester);
  a_vs_b_tester.Test("cccc00011111nnnntttt111110011111");
}

// op(23:20)=0x00 & $pattern(31:0)=xxxxxxxxxxxxxxxxxxxx0000xxxxxxxx
//    = {actual: Deprecated,
//       baseline: Deprecated,
//       constraints: ,
//       pattern: cccc00010b00nnnntttt00001001tttt,
//       rule: SWP_SWPB}
TEST_F(Arm32DecoderStateTests,
       DeprecatedTester_Case8_TestCase8) {
  DeprecatedTester_Case8 tester;
  tester.Test("cccc00010b00nnnntttt00001001tttt");
}

}  // namespace nacl_arm_test

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
