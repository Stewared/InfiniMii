


void FUN_7100ba77b0(long param_1)

{
  FUN_71005fc26c(param_1);
  ret_71005FC268();
  return;
}



undefined1  [16] FUN_7100ba77dc(uint param_1,float *param_2,int param_3)

{
  uint uVar1;
  undefined1 auVar2 [16];
  undefined4 uVar3;
  undefined4 extraout_s0;
  undefined4 extraout_var;
  undefined8 extraout_var_00;
  
  if (((param_3 != 1) && (param_1 < 0xf)) && ((1 << (ulong)(param_1 & 0x1f) & 0x61c0U) != 0)) {
    uVar1 = param_1 - 6;
    uVar3 = 0x3f800000;
    if ((uVar1 < 9) && ((0x187U >> (ulong)(uVar1 & 0x1f) & 1) != 0)) {
      uVar3 = *(undefined4 *)
               (&DAT_71032a8be4 + *(long *)(&DAT_71032a8c08 + (long)(int)uVar1 * 8) * 8);
    }
    thunk_EXT_FUN_02e95df0
              (uVar3,(param_2[1] * 0.587 + *param_2 * 0.299 + param_2[2] * 0.114) * 1.8 + 0.2 + -1.0
              );
    auVar2._4_4_ = extraout_var;
    auVar2._0_4_ = extraout_s0;
    auVar2._8_8_ = extraout_var_00;
    return auVar2;
  }
  return ZEXT416(0x3f800000);
}



void FUN_7100ba78e4(undefined8 *param_1)

{
  FUN_71005fbcfc(param_1);
  *param_1 = 0x1000000040;
  return;
}



void FUN_7100ba7910(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  uVar1 = param_2[2];
  param_1[3] = 0x3f800000;
  param_1[2] = uVar1;
  return;
}



void FUN_7100ba7940(long param_1,long param_2,ulong param_3)

{
  long lVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  ulong uVar5;
  ushort uVar6;
  ulong uVar7;
  ulong uVar8;
  
  if (0 < (int)(param_3 / 0xc)) {
    uVar7 = 0;
    do {
      uVar8 = (ulong)(uint)((int)uVar7 * 3);
      uVar3 = *(uint *)(param_2 + uVar8 * 4);
      uVar2 = uVar3 & 0x7fffffff;
      if (uVar2 < 0x47800000) {
        uVar4 = uVar2 >> 0x17;
        if (uVar4 < 0x71) {
          if (uVar2 >> 0x18 < 0x33) {
            uVar6 = 0;
          }
          else {
            uVar2 = uVar3 & 0x7fffff | 0x800000;
            uVar6 = (ushort)(uVar2 + ~(-1 << (ulong)(0x7d - uVar4 & 0x1f)) +
                             (uVar2 >> (ulong)(0x7e - uVar4 & 0x1f) & 1) >>
                            (ulong)(0x7e - uVar4 & 0x1f));
          }
        }
        else {
          uVar6 = (ushort)(uVar2 + 0xc8000fff + (uVar3 >> 0xd & 1) >> 0xd);
        }
      }
      else if (uVar2 < 0x7f800001) {
        uVar6 = 0x7c00;
      }
      else {
        uVar6 = (ushort)(uVar3 >> 0xd) & 0x1ff | 0x7e00;
      }
      uVar5 = (ulong)(uint)((int)uVar7 << 2);
      *(ushort *)(param_1 + uVar5 * 2) = uVar6 | (ushort)((uVar3 >> 0x1f) << 0xf);
      lVar1 = param_2 + uVar8 * 4;
      uVar3 = *(uint *)(lVar1 + 4);
      uVar2 = uVar3 & 0x7fffffff;
      if (uVar2 < 0x47800000) {
        uVar4 = uVar2 >> 0x17;
        if (uVar4 < 0x71) {
          if (uVar2 >> 0x18 < 0x33) {
            uVar6 = 0;
          }
          else {
            uVar2 = uVar3 & 0x7fffff | 0x800000;
            uVar6 = (ushort)(uVar2 + ~(-1 << (ulong)(0x7d - uVar4 & 0x1f)) +
                             (uVar2 >> (ulong)(0x7e - uVar4 & 0x1f) & 1) >>
                            (ulong)(0x7e - uVar4 & 0x1f));
          }
        }
        else {
          uVar6 = (ushort)(uVar2 + 0xc8000fff + (uVar3 >> 0xd & 1) >> 0xd);
        }
      }
      else {
        uVar6 = 0x7c00;
        if (0x7f800000 < uVar2) {
          uVar6 = (ushort)(uVar3 >> 0xd) & 0x1ff | 0x7e00;
        }
      }
      uVar5 = uVar5 << 1;
      *(ushort *)(param_1 + (uVar5 | 2)) = uVar6 | (ushort)((uVar3 >> 0x1f) << 0xf);
      uVar3 = *(uint *)(lVar1 + 8);
      uVar2 = uVar3 & 0x7fffffff;
      if (uVar2 < 0x47800000) {
        uVar4 = uVar2 >> 0x17;
        if (uVar4 < 0x71) {
          if (uVar2 >> 0x18 < 0x33) {
            uVar6 = 0;
          }
          else {
            uVar2 = uVar3 & 0x7fffff | 0x800000;
            uVar6 = (ushort)(uVar2 + ~(-1 << (ulong)(0x7d - uVar4 & 0x1f)) +
                             (uVar2 >> (ulong)(0x7e - uVar4 & 0x1f) & 1) >>
                            (ulong)(0x7e - uVar4 & 0x1f));
          }
        }
        else {
          uVar6 = (ushort)(uVar2 + 0xc8000fff + (uVar3 >> 0xd & 1) >> 0xd);
        }
      }
      else if (uVar2 < 0x7f800001) {
        uVar6 = 0x7c00;
      }
      else {
        uVar6 = (ushort)(uVar3 >> 0xd) & 0x1ff | 0x7e00;
      }
      *(undefined2 *)(param_1 + (uVar5 | 6)) = 0x3c00;
      uVar7 = uVar7 + 1;
      *(ushort *)(param_1 + (uVar5 | 4)) = uVar6 | (ushort)((uVar3 >> 0x1f) << 0xf);
    } while (uVar7 != (param_3 / 0xc & 0xffffffff));
  }
  return;
}



void FUN_7100ba7b90(long param_1,long param_2)

{
  FUN_7100ba7940(param_1,param_2,0xc);
  return;
}



void FUN_7100ba7ba0(ushort *param_1,uint *param_2,ulong param_3)

{
  uint uVar1;
  uint uVar2;
  ushort uVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  ulong uVar7;
  
  if (0 < (int)(param_3 >> 2)) {
    uVar7 = param_3 >> 2 & 0xffffffff;
    do {
      while( true ) {
        uVar5 = *param_2;
        uVar1 = uVar5 & 0x7fffffff;
        if ((uVar5 >> 0x17 & 0xff) < 0x8f) break;
        uVar4 = 0x7c00;
        if (0x7f800000 < uVar1) {
          uVar4 = (ushort)(uVar5 >> 0xd) & 0x1ff | 0x7e00;
        }
        uVar7 = uVar7 - 1;
        *param_1 = uVar4 | (ushort)((uVar5 >> 0x1f) << 0xf);
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        if (uVar7 == 0) {
          return;
        }
      }
      uVar6 = uVar1 >> 0x17;
      uVar2 = uVar5 & 0x7fffff | 0x800000;
      uVar4 = 0;
      if (0x32 < uVar1 >> 0x18) {
        uVar4 = (ushort)(uVar2 + ~(-1 << (ulong)(0x7d - uVar6 & 0x1f)) +
                         (uVar2 >> (ulong)(0x7e - uVar6 & 0x1f) & 1) >> (ulong)(0x7e - uVar6 & 0x1f)
                        );
      }
      uVar3 = (ushort)(uVar1 + (uVar5 >> 0xd & 1) + 0xc8000fff >> 0xd);
      if (uVar6 < 0x71) {
        uVar3 = uVar4;
      }
      uVar7 = uVar7 - 1;
      *param_1 = uVar3 | (ushort)((uVar5 >> 0x1f) << 0xf);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
    } while (uVar7 != 0);
  }
  return;
}



void FUN_7100ba7c78(undefined8 *param_1)

{
  *(undefined4 *)(param_1 + 0xd) = 0;
  *param_1 = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}
