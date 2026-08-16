


long FUN_7100ba7448(long param_1)

{
  return param_1 + 0x48;
}



long FUN_7100ba7450(long param_1)

{
  return param_1 + 0x90;
}



undefined8 FUN_7100ba7458(void)

{
  return 6;
}



undefined8 FUN_7100ba7460(void)

{
  return 0x20;
}



undefined8 FUN_7100ba7468(void)

{
  return 0x10;
}



undefined8 FUN_7100ba7470(void)

{
  return 0xc;
}



uint FUN_7100ba7478(undefined8 *param_1)

{
  uint uVar1;
  undefined8 local_30;
  undefined8 uStack_28;
  
  local_30 = 0;
  uStack_28 = 0;
  FUN_71005fbcfc(&local_30);
  local_30 = 0x400000020;
  uVar1 = FUN_71005fbfe4(param_1,(long)&local_30);
  return uVar1;
}



uint FUN_7100ba74c0(undefined8 *param_1)

{
  uint uVar1;
  undefined8 local_30;
  undefined8 uStack_28;
  
  local_30 = 0;
  uStack_28 = 0;
  FUN_71005fbcfc(&local_30);
  local_30 = 0x400000010;
  uVar1 = FUN_71005fbfe4(param_1,(long)&local_30);
  return uVar1;
}



uint FUN_7100ba7508(undefined8 *param_1)

{
  uint uVar1;
  undefined8 local_30;
  undefined8 uStack_28;
  
  local_30 = 0;
  uStack_28 = 0;
  FUN_71005fbcfc(&local_30);
  local_30 = 0x80000000c;
  uVar1 = FUN_71005fbfe4(param_1,(long)&local_30);
  return uVar1;
}



void FUN_7100ba7550(undefined1 *param_1,undefined8 *param_2,undefined8 *param_3,uint *param_4)

{
  uint uVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  
  uVar1 = FUN_71005fbfe4(param_3,(long)param_4);
  FUN_7100ba7ea4((long)param_2,(ulong)uVar1);
  puVar2 = (undefined8 *)FUN_7100ba7ec0(param_2);
  uVar3 = FUN_7100ba7ec8((long)param_2);
  FUN_71005fc12c(param_1,param_3,param_4,puVar2,uVar3);
  FUN_7100ba7ed0((long)param_2,(ulong)*param_4);
  return;
}



void FUN_7100ba75e0(undefined1 *param_1,undefined8 *param_2,undefined8 *param_3,byte *param_4)

{
  long lVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  
  lVar1 = FUN_710060406c(param_3,param_4);
  FUN_7100ba7ea4((long)param_2,lVar1);
  lVar1 = FUN_71006040e8(param_3,param_4);
  puVar2 = (undefined8 *)FUN_7100ba7ec0(param_2);
  uVar3 = FUN_7100ba7ec8((long)param_2);
  FUN_710060424c(param_1,param_3,param_4,puVar2,uVar3);
  FUN_7100ba7ed0((long)param_2,lVar1);
  return;
}



int FUN_7100ba7680(int param_1)

{
  return param_1 >> 8;
}



undefined1 FUN_7100ba7690(undefined1 param_1)

{
  return param_1;
}



uint FUN_7100ba76a0(int param_1,uint param_2)

{
  return param_2 | param_1 << 8;
}



void FUN_7100ba76b0(long param_1,long param_2,uint param_3,uint param_4,int param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined8 local_a0;
  undefined8 uStack_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined4 local_80;
  undefined8 local_78;
  undefined8 uStack_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined4 local_58;
  
  if (1 < param_5) {
    iVar3 = 1;
    do {
      if ((param_3 == 1) && (param_4 == 1)) {
        return;
      }
      local_58 = 0;
      local_68 = 0;
      local_60 = 0;
      local_78 = 0;
      uStack_70 = 0;
      FUN_71005fbfc8(&local_78);
      uVar1 = param_3 >> 1;
      uStack_70 = CONCAT44(param_3,(undefined4)uStack_70);
      local_68 = CONCAT44(local_68._4_4_,param_4);
      if ((int)param_3 < 2) {
        uVar1 = 1;
      }
      uVar2 = param_4 >> 1;
      local_60 = CONCAT62(local_60._2_6_,(short)iVar3 + -1);
      local_80 = 0;
      if ((int)param_4 < 2) {
        uVar2 = 1;
      }
      local_90 = 0;
      local_88 = 0;
      local_a0 = 0;
      uStack_98 = 0;
      FUN_71005fbfc8(&local_a0);
      uStack_98 = CONCAT44(uVar1,(undefined4)uStack_98);
      local_90 = CONCAT44(local_90._4_4_,uVar2);
      local_88 = CONCAT62(local_88._2_6_,(short)iVar3);
      FUN_71005fcc54(param_1,param_2,(undefined4 *)&local_a0,param_2,(undefined4 *)&local_78,1);
      iVar3 = iVar3 + 1;
      param_4 = uVar2;
      param_3 = uVar1;
    } while (param_5 != iVar3);
  }
  return;
}
