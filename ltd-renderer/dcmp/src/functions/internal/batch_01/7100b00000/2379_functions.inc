


void FUN_7100ba6e94(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return;
}



void FUN_7100ba6e9c(long param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 4) = param_2;
  return;
}



undefined4 FUN_7100ba6eac(undefined4 *param_1)

{
  return *param_1;
}



undefined4 FUN_7100ba6eb4(long param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



undefined1 FUN_7100ba6ebc(long param_1)

{
  return *(undefined1 *)(param_1 + 8);
}



void FUN_7100ba6ec4(undefined4 param_1,undefined4 *param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  
  iVar4 = (int)(param_3 << 8) >> 0x18;
  iVar5 = (int)(param_4 << 0x10) >> 0x18;
  *param_2 = param_1;
  iVar6 = (int)(param_3 << 0x10) >> 0x18;
  iVar7 = (int)(param_4 << 8) >> 0x18;
  uVar2 = iVar7 * iVar6 - iVar5 * iVar4;
  uVar3 = iVar4 * param_4 - iVar7 * param_3;
  uVar1 = (iVar5 * param_3 - iVar6 * param_4) * 0x10000;
  if ((uVar2 & 1) == 0) {
    uVar8 = 1;
    if ((uVar3 & 1) == 0) {
      uVar8 = uVar1 >> 0xf & 2;
    }
    param_2[1] = uVar8;
  }
  else {
    param_2[1] = 0;
  }
  if ((param_3 & 1) == 0) {
    if ((param_3 >> 8 & 1) == 0) {
      param_2[2] = param_3 >> 0xf & 2;
    }
    else {
      param_2[2] = 1;
    }
  }
  else {
    param_2[2] = 0;
  }
  if ((param_4 & 1) == 0) {
    if ((param_4 >> 8 & 1) == 0) {
      uVar8 = param_4 >> 0xf & 2;
    }
    else {
      uVar8 = 1;
    }
  }
  else {
    uVar8 = 0;
  }
  param_2[3] = uVar8;
  *(bool *)(param_2 + 4) = (uVar1 & 0x100000) != 0 || ((uVar2 & 0x10) != 0 || (uVar3 >> 4 & 1) != 0)
  ;
  *(bool *)((long)param_2 + 0x11) = (param_3 & 0x101010) != 0;
  *(bool *)((long)param_2 + 0x12) = (param_4 & 0x101010) != 0;
  return;
}
