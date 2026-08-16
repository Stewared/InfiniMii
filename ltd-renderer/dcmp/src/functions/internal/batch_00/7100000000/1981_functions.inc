


void FUN_7100000170(void)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  
  FUN_7100000260(0x71037bfdb8,0,DAT_7103e3b780);
  puVar1 = DAT_7103a59ab0;
  puVar2 = DAT_7103a59ab8;
  while (puVar1 < puVar2) {
    puVar2 = puVar2 + -1;
    (*(code *)*puVar2)();
  }
  return;
}



undefined8 FUN_71000001d0(undefined8 param_1,undefined8 param_2,long param_3)

{
  char cVar1;
  bool bVar2;
  ulong uVar3;
  ulong uVar4;
  undefined8 *puVar5;
  
  if ((param_3 != 0) &&
     (uVar4 = (DAT_7103a59ac8 - DAT_7103a59ac0 >> 3) * -0x5555555555555555,
     DAT_7103e3b780 <= uVar4 && uVar4 - DAT_7103e3b780 != 0)) {
    do {
      uVar3 = DAT_7103e3b780;
      cVar1 = '\x01';
      bVar2 = (bool)ExclusiveMonitorPass(0x7103e3b780,0x10);
      if (bVar2) {
        cVar1 = ExclusiveMonitorsStatus();
        DAT_7103e3b780 = DAT_7103e3b780 + 1;
      }
    } while (cVar1 != '\0');
    if (uVar3 <= uVar4 && uVar4 - uVar3 != 0) {
      puVar5 = (undefined8 *)(DAT_7103a59ac0 + uVar3 * 0x18);
      puVar5[2] = param_3;
      *puVar5 = param_1;
      puVar5[1] = param_2;
      return 0;
    }
  }
  return 0xffffffff;
}



void FUN_7100000260(long param_1,ulong param_2,ulong param_3)

{
  ulong uVar1;
  ulong uVar2;
  long *plVar3;
  
  uVar2 = (DAT_7103a59ac8 - DAT_7103a59ac0 >> 3) * -0x5555555555555555;
  if (param_3 <= uVar2) {
    uVar2 = param_3;
  }
  if (param_2 < uVar2) {
    plVar3 = (long *)(DAT_7103a59ac0 + uVar2 * 0x18 + -8);
    do {
      uVar1 = DAT_7103e3b780;
      if (*plVar3 == param_1) {
        (*(code *)plVar3[-2])(plVar3[-1]);
      }
      uVar2 = uVar2 - 1;
      FUN_7100000260(param_1,uVar1,DAT_7103e3b780);
      plVar3 = plVar3 + -3;
    } while (param_2 < uVar2);
  }
  return;
}



void FUN_7100000350(long *param_1,undefined8 *param_2,undefined8 *param_3)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  
  *param_2 = 0x5afb00;
  lVar3 = 0;
  *param_3 = 0x3000;
  *param_1 = 0;
  lVar2 = DAT_7103a68d40;
  lVar4 = 0;
  while( true ) {
    lVar1 = lVar2 + lVar3;
    lVar4 = (*(long *)(lVar1 + 0x20) + 0xffU & 0xffffffffffffff00) + lVar4;
    *param_1 = lVar4;
    if (lVar3 == 0xc80) break;
    lVar3 = lVar3 + 0x50;
    lVar4 = (*(long *)(lVar1 + 0x48) + 0xffU & 0xffffffffffffff00) + lVar4;
    *param_1 = lVar4;
  }
  return;
}



void FUN_71000003c0(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  *param_2 = 0x100;
  *param_3 = 8;
  *param_1 = 0x100;
  return;
}



bool FUN_71000003d8(long param_1)

{
  long lVar1;
  
  (*(code *)*DAT_7103a64a58)(*(undefined8 *)(param_1 + 0x2f0),0,8);
  lVar1 = (*(code *)*DAT_7103a64b20)(*(undefined8 *)(param_1 + 0x2f0));
  return *(short *)(lVar1 + 6) == 0 && *(char *)(param_1 + 0x10) == '\0';
}



undefined8
FUN_7100000440(auto_FUN_7100000440_param_1 *param_1,undefined4 param_2,undefined8 param_3,
              undefined8 param_4,long param_5)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  long lVar3;
  long lVar4;
  undefined8 *puVar5;
  long lVar6;
  code *pcVar7;
  long *plVar8;
  long lVar9;
  undefined1 *puVar10;
  ulong uVar11;
  long local_330;
  long lStack_328;
  auto_FUN_710000b8b8_param_3 local_2f0 [7];
  
  puVar5 = DAT_7103a64b20;
  uVar2 = (*(code *)*DAT_7103a64b20)(param_5);
  thunk_EXT_FUN_02e95df0(uVar2,DAT_7103a68d50,0x8f704);
  (*(code *)*DAT_7103a64a40)(param_5,0,0x8f704);
  lVar3 = (*(code *)*puVar5)(param_4);
  lVar4 = (*(code *)*DAT_7103a64a50)(param_4);
  puVar1 = DAT_7103a678f0;
  puVar5 = DAT_7103a678e8;
  lVar9 = 0;
  uVar11 = 0;
  puVar10 = (undefined1 *)((long)&param_1[7].field_0x60_r + 6);
  plVar8 = (long *)(DAT_7103a68d40 + 0x20);
  do {
    thunk_EXT_FUN_02e95df0(lVar3 + uVar11,plVar8[-3],*plVar8);
    (*(code *)*DAT_7103a64a40)(param_4,uVar11,*plVar8 + uVar11);
    lStack_328 = plVar8[-4];
    local_330 = uVar11 + lVar4;
    (*(code *)*puVar5)(puVar10,param_3);
    (*(code *)*puVar1)(puVar10,1,&local_330);
    lVar6 = *plVar8;
    *(undefined1 **)(&local_2f0[0].field_0x0 + lVar9) = puVar10;
    lVar9 = lVar9 + 8;
    puVar10 = puVar10 + 0x80;
    uVar11 = (uVar11 | 7) + lVar6 & 0xfffffffffffffff8;
    plVar8 = plVar8 + 5;
  } while (lVar9 != 0x288);
  uVar2 = (*(code *)*DAT_7103a64a50)(param_5);
  *(long *)&param_1[4].field_0x78 = param_5;
  FUN_710000b8b8((auto_FUN_710000b8b8_param_1 *)&param_1->field_0x50,uVar2,local_2f0);
  lVar9 = *(long *)param_1;
  *(undefined4 *)((long)&param_1->field_0x9_w + 3) = 0;
  *(undefined2 *)((long)&param_1->field_0x9_w + 7) = 0;
  *(undefined8 *)&param_1->field_0x14 = 0;
  (**(code **)(lVar9 + 0x28))(param_1,0,1);
  (**(code **)(*(long *)param_1 + 0x18))(param_1,param_2,1);
  *(undefined4 *)&param_1->field_0x2c = param_2;
  puVar1 = DAT_7103a64b20;
  uVar2 = *(undefined8 *)&param_1[4].field_0x78;
  pcVar7 = (code *)*DAT_7103a64b20;
  *(undefined8 *)&param_1->field_0x40 = 0;
  *(undefined8 *)&param_1->field_0x48 = 0x100000000;
  puVar5 = (undefined8 *)(*pcVar7)(uVar2);
  *puVar5 = 0x1000000000000;
  puVar5 = DAT_7103a64a40;
  (*(code *)*DAT_7103a64a40)(*(undefined8 *)&param_1[4].field_0x78,0,8);
  lVar9 = (*(code *)*puVar1)(*(undefined8 *)&param_1[4].field_0x78);
  *(undefined1 *)(lVar9 + 0x5afa00) = 0x3a;
  (*(code *)*puVar5)(*(undefined8 *)&param_1[4].field_0x78,0x5afa00,1);
  lVar9 = FUN_71005fbcb0(0x1000,*(long *)&param_1[4].field_0x80 + 0xfffU & 0xfffffffffffff000);
  *(long *)&param_1[7].field_0x5e = lVar9;
  (*(code *)*DAT_7103a64b28)(&local_330);
  (*(code *)*DAT_7103a64b30)(&local_330,param_3);
  (*(code *)*DAT_7103a64b38)(&local_330,0x12);
  (*(code *)*DAT_7103a64b40)
            (&local_330,*(undefined8 *)&param_1[7].field_0x5e,*(undefined8 *)&param_1[4].field_0x80)
  ;
  (*(code *)*DAT_7103a64b48)(&param_1[5].field_0x92,&local_330);
  (*(code *)*DAT_7103a68d58)(&param_1[4].field_0x90,param_3);
  lVar9 = FUN_71005fbcb0(8,*(undefined8 *)&param_1[4].field_0x88);
  *(long *)&param_1[7].field_0x56 = lVar9;
  return 0;
}



void FUN_7100000764(undefined8 *param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4,
                   long param_5,auto_FUN_7100000764_param_6 *param_6)

{
  *(undefined4 *)((long)&param_6->field_0x9_w + 3) = 0;
  *(undefined8 *)&param_6->field_0x1c = 0xffffffff00000000;
  *(undefined8 *)&param_6->field_0x2c = 0xffffffff00000000;
  *(undefined8 *)&param_6->field_0x34 = 0xffffffff;
  *(undefined2 *)((long)&param_6->field_0x9_w + 7) = 0;
  *(undefined8 *)&param_6->field_0x14 = 0;
  param_6->field_0x28 = 0;
  *(undefined8 *)&param_6->field_0x40 = 0;
  *(undefined8 *)&param_6->field_0x48 = 0x100000000;
  *(undefined **)param_6 = &DAT_71037bfdd0;
  *(undefined8 *)&param_6[7].field_0x20 = 0x10000;
  *(undefined8 *)&param_6[7].field_0x28 = 0x8000;
  FUN_7100000440((auto_FUN_7100000440_param_1 *)param_6,param_2,param_3,param_4,param_5);
  *param_1 = param_6;
  return;
}



void FUN_710000086c(undefined8 *param_1)

{
  (**(code **)(*(long *)*param_1 + 0x38))();
  *param_1 = 0;
  return;
}



void FUN_71000008d0(long param_1,undefined8 param_2)

{
  long lVar1;
  undefined8 local_18;
  
  lVar1 = param_1 + 0x308;
  (*(code *)*DAT_7103a68d68)
            (lVar1,*(undefined8 *)(param_1 + 0x4a8),*(undefined8 *)(param_1 + 0x300));
  (*(code *)*DAT_7103a68d70)(lVar1,param_1 + 0x3a8,0,*(undefined8 *)(param_1 + 0x2f8));
  (*(code *)*DAT_7103a68d78)(lVar1);
  FUN_710000b71c((auto_FUN_710000b71c_param_1 *)(param_1 + 0x50),lVar1);
  local_18 = (*(code *)*DAT_7103a68d80)(lVar1);
  (*(code *)*DAT_7103a68d88)(param_2,1,&local_18);
  (*(code *)*DAT_7103a68d90)(param_2);
  (*(code *)*DAT_7103a68d98)(param_2);
  return;
}



void FUN_71000009b4(undefined8 *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0071000009c0. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*(long *)*param_1 + 0x48))();
  return;
}



void FUN_71000009c4(long param_1,int param_2,ulong param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  if ((param_3 & 1) == 0) {
    if ((param_2 != 1) || (*(int *)(param_1 + 0x1c) == 1)) {
      if ((param_2 != 0) || (*(int *)(param_1 + 0x1c) == 0)) goto LAB_71000009ec;
      goto LAB_7100000abc;
    }
  }
  else {
    if (param_2 == 0) {
LAB_7100000abc:
      thunk_EXT_FUN_02e95df0(param_1 + 0x2d38,&DAT_7102ebf378,0xc4);
      thunk_EXT_FUN_02e95df0(param_1 + 0x2dfc,&DAT_7102ebf43c,0x94);
      thunk_EXT_FUN_02e95df0(param_1 + 0x2e90,&DAT_7102ebf4d0,0x94);
      thunk_EXT_FUN_02e95df0(param_1 + 0x2f24,&DAT_7102ebf564,200);
      uVar2 = 0x3fa8f5c3;
      uVar4 = 0x3e6147ae;
      uVar3 = 0x3eb33333;
      uVar5 = 0x3f0a3d71;
      uVar1 = 0x3e3851ec;
      goto LAB_7100000b58;
    }
    if (param_2 != 1) {
LAB_71000009ec:
      *(int *)(param_1 + 0x1c) = param_2;
      return;
    }
  }
  thunk_EXT_FUN_02e95df0(param_1 + 0x2d38,&DAT_7102ebf0c4,0xc4);
  thunk_EXT_FUN_02e95df0(param_1 + 0x2dfc,&DAT_7102ebf188,0x94);
  thunk_EXT_FUN_02e95df0(param_1 + 0x2e90,&DAT_7102ebf21c,0x94);
  thunk_EXT_FUN_02e95df0(param_1 + 0x2f24,&DAT_7102ebf2b0,200);
  uVar2 = 0x3f051eb8;
  uVar4 = 0x3db851ec;
  uVar3 = 0x3e051eb8;
  uVar5 = 0x3e6147ae;
  uVar1 = 0x3da3d70a;
LAB_7100000b58:
  *(undefined4 *)(param_1 + 0x2ff0) = uVar5;
  *(undefined4 *)(param_1 + 0x2ff4) = uVar4;
  *(undefined4 *)(param_1 + 0x2ff8) = uVar3;
  *(undefined4 *)(param_1 + 0x2ffc) = uVar2;
  *(undefined4 *)(param_1 + 0x2fec) = uVar1;
  *(int *)(param_1 + 0x1c) = param_2;
  return;
}



undefined8
FUN_7100000b84(long param_1,undefined8 param_2,int param_3,int param_4,int param_5,
              undefined8 param_6)

{
  long lVar1;
  undefined8 uVar2;
  long lVar3;
  undefined8 local_38;
  
  lVar1 = param_1 + 0x308;
  (*(code *)*DAT_7103a68d68)
            (lVar1,*(undefined8 *)(param_1 + 0x4a8),*(undefined8 *)(param_1 + 0x300));
  (*(code *)*DAT_7103a68d70)(lVar1,param_1 + 0x3a8,0,*(undefined8 *)(param_1 + 0x2f8));
  (*(code *)*DAT_7103a68d78)(lVar1);
  uVar2 = 3;
  *(undefined1 *)(param_1 + 0x10) = 1;
  if (((param_3 == param_4) && (param_5 == 4)) && ((param_3 == 0x100 || (param_3 == 0x80)))) {
    if ((*(int *)(param_1 + 0x14) != param_3) || (*(int *)(param_1 + 0x18) != param_3)) {
      *(undefined1 *)(param_1 + 0x11) = 1;
      lVar3 = (*DAT_7103ff3ae8)(*(undefined8 *)(param_1 + 0x2f0));
      *(short *)(lVar3 + 4) = (short)param_3;
      (*(code *)*DAT_7103a64a40)(*(undefined8 *)(param_1 + 0x2f0),0,8);
    }
    *(int *)(param_1 + 0x14) = param_3;
    *(int *)(param_1 + 0x18) = param_3;
    FUN_710000bb48((auto_FUN_710000bb48_param_1 *)(param_1 + 0x50),param_2,param_3 * param_3 * 4,
                   lVar1);
    local_38 = (*(code *)*DAT_7103a68d80)(lVar1);
    (*(code *)*DAT_7103a68d88)(param_6,1,&local_38);
    (*(code *)*DAT_7103a68d90)(param_6);
    (*(code *)*DAT_7103a68d98)(param_6);
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_7100000d1c(auto_FUN_7100000d1c_param_1 *param_1,auto_FUN_7100000d1c_param_2 *param_2,
                   undefined8 param_3)

{
  auto_FUN_710000b71c_param_1 *paVar1;
  undefined1 *puVar2;
  auto_FUN_710000b5e8_param_1 *paVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  long lVar8;
  int iVar9;
  uint uVar10;
  byte *pbVar11;
  long lVar12;
  undefined4 uVar13;
  long lVar14;
  double dVar15;
  
  lVar8 = DAT_7103a68d38;
  iVar9 = *(int *)((long)&param_1[2].field_0x4_r + 4);
  if (iVar9 < 0x22e) {
    if (iVar9 == 0x205) goto LAB_7100000e04;
    if (iVar9 == 0x21f) goto LAB_7100000ebc;
  }
  else {
    if (iVar9 == 0x22e) goto LAB_7100000f04;
    if (iVar9 == 0x249) {
      iVar9._0_1_ = param_2->field_0x24_w;
      iVar9._1_1_ = param_2->field_0x25_w;
      iVar9._2_1_ = param_2->field_0x26_w;
      iVar9._3_1_ = param_2->field_0x27_w;
      goto LAB_7100000f2c;
    }
  }
LAB_7100000d7c:
  do {
    paVar1 = (auto_FUN_710000b71c_param_1 *)((long)&param_1[6].field_0x4_r + 4);
    FUN_710000bc38((long)paVar1,param_3);
    iVar9 = *(int *)((long)&param_1->field_0x4_r + 4);
    if (iVar9 != *(int *)&param_2->field_0x4) {
      (**(code **)(*(long *)param_1 + 0x18))(param_1,iVar9,1);
      uVar13 = *(undefined4 *)((long)&param_1->field_0x4_r + 4);
      *(undefined1 *)param_2 = 1;
      puVar2 = (undefined1 *)((long)&param_1[0x40].field_0x4_r + 4);
      *(undefined4 *)&param_2->field_0x4 = uVar13;
      FUN_710000b71c(paVar1,puVar2);
      FUN_710000b7e8((auto_FUN_710000b7e8_param_1 *)paVar1,puVar2);
      dVar15 = *(double *)&param_2->field_0x18_w +
               (double)*(float *)((long)&param_1[0x3ff].field_0x4_r + 4);
      *(double *)&param_2->field_0x18_w = dVar15;
      if ((double)*(float *)&param_2->field_0x10 <= dVar15) {
        uVar13 = 0x205;
        goto LAB_7100001028;
      }
    }
LAB_7100000e04:
    if (*(char *)((long)&param_1[1].field_0x4_r + 1) != '\0' || *(char *)param_2 != '\0') {
      *(undefined4 *)&param_2->field_0x8 = *(undefined4 *)((long)&param_1[1].field_0x4_r + 4);
      uVar13 = *(undefined4 *)(param_1 + 2);
      param_2->field_0x20_w = 0;
      param_2->field_0x21_w = 0;
      param_2->field_0x22_w = 0;
      param_2->field_0x23_w = 0;
      param_2->field_0x24_w = 1;
      param_2->field_0x25_w = 0;
      param_2->field_0x26_w = 0;
      param_2->field_0x27_w = 0;
      *(undefined1 *)param_2 = 0;
      *(undefined4 *)&param_2->field_0xc = uVar13;
      *(undefined1 *)((long)&param_1[1].field_0x4_r + 1) = 0;
      FUN_710000bc40((auto_FUN_710000bc40_param_1 *)((long)&param_1[6].field_0x4_r + 4),
                     (undefined1 *)((long)&param_1[0x40].field_0x4_r + 4));
      *(double *)&param_2->field_0x18_w = *(double *)&param_2->field_0x18_w + 0.009999999776482582;
    }
    puVar2 = (undefined1 *)((long)&param_1[0x40].field_0x4_r + 4);
    paVar3 = (auto_FUN_710000b5e8_param_1 *)((long)&param_1[6].field_0x4_r + 4);
    FUN_710000b5e8(paVar3,puVar2);
    FUN_710000b240((auto_FUN_710000b240_param_1 *)paVar3,*(undefined4 *)(param_1 + 1),puVar2,0);
    pbVar11 = &param_2->field_0x18_w;
    *(double *)pbVar11 =
         *(double *)pbVar11 +
         (double)*(float *)((long)&param_1[0x3fe].field_0x4_r + (long)*(int *)(param_1 + 1) * 4);
    *(undefined1 *)&param_1[1].field_0x4_r = 0;
    if ((double)*(float *)&param_2->field_0x10 <= *(double *)pbVar11) {
      uVar13 = 0x21f;
LAB_7100001028:
      param_2->field_0x18_w = 0;
      param_2->field_0x19_w = 0;
      param_2->field_0x1A_w = 0;
      param_2->field_0x1B_w = 0;
      param_2->field_0x1C_w = 0;
      param_2->field_0x1D_w = 0;
      param_2->field_0x1E_w = 0;
      param_2->field_0x1F_w = 0;
      *(undefined4 *)((long)&param_1[2].field_0x4_r + 4) = uVar13;
      return;
    }
LAB_7100000ebc:
    if ((char)param_1[1].field_0x4_r == '\0') {
LAB_7100000ec4:
      FUN_710000bcdc((auto_FUN_710000bcdc_param_1 *)((long)&param_1[6].field_0x4_r + 4),
                     (undefined1 *)((long)&param_1[0x40].field_0x4_r + 4),0);
      dVar15 = *(double *)&param_2->field_0x18_w + 0.009999999776482582;
      *(double *)&param_2->field_0x18_w = dVar15;
      if (dVar15 < (double)*(float *)&param_2->field_0x10) {
LAB_7100000f04:
        if (*(char *)((long)&param_1[1].field_0x4_r + 1) == '\0') {
          iVar9._0_1_ = param_2->field_0x20_w;
          iVar9._1_1_ = param_2->field_0x21_w;
          iVar9._2_1_ = param_2->field_0x22_w;
          iVar9._3_1_ = param_2->field_0x23_w;
          uVar10._0_1_ = param_2->field_0x24_w;
          uVar10._1_1_ = param_2->field_0x25_w;
          uVar10._2_1_ = param_2->field_0x26_w;
          uVar10._3_1_ = param_2->field_0x27_w;
          do {
            puVar2 = (undefined1 *)((long)&param_1[0x40].field_0x4_r + 4);
            FUN_71000012b4((auto_FUN_71000012b4_param_1 *)((long)&param_1[6].field_0x4_r + 4),
                           *(undefined4 *)(param_1 + 1),puVar2,iVar9,uVar10);
            (*(code *)*DAT_7103a633f0)(puVar2,1);
            switch(*(undefined4 *)(param_1 + 1)) {
            case 0:
              iVar4._0_1_ = param_2->field_0x20_w;
              iVar4._1_1_ = param_2->field_0x21_w;
              iVar4._2_1_ = param_2->field_0x22_w;
              iVar4._3_1_ = param_2->field_0x23_w;
              lVar12 = (long)iVar4;
              lVar14 = 0x2d38;
              break;
            case 1:
              iVar5._0_1_ = param_2->field_0x20_w;
              iVar5._1_1_ = param_2->field_0x21_w;
              iVar5._2_1_ = param_2->field_0x22_w;
              iVar5._3_1_ = param_2->field_0x23_w;
              lVar12 = (long)iVar5;
              lVar14 = 0x2f24;
              break;
            case 2:
              iVar6._0_1_ = param_2->field_0x20_w;
              iVar6._1_1_ = param_2->field_0x21_w;
              iVar6._2_1_ = param_2->field_0x22_w;
              iVar6._3_1_ = param_2->field_0x23_w;
              lVar12 = (long)iVar6;
              lVar14 = 0x2dfc;
              break;
            case 3:
              iVar7._0_1_ = param_2->field_0x20_w;
              iVar7._1_1_ = param_2->field_0x21_w;
              iVar7._2_1_ = param_2->field_0x22_w;
              iVar7._3_1_ = param_2->field_0x23_w;
              lVar12 = (long)iVar7;
              lVar14 = 0x2e90;
              break;
            default:
              goto switchD_7100000fa4_default;
            }
            *(double *)&param_2->field_0x18_w =
                 *(double *)&param_2->field_0x18_w +
                 (double)*(float *)(&param_1->field_0x0 + lVar14 + lVar12 * 4);
switchD_7100000fa4_default:
            iVar9._0_1_ = param_2->field_0x24_w;
            iVar9._1_1_ = param_2->field_0x25_w;
            iVar9._2_1_ = param_2->field_0x26_w;
            iVar9._3_1_ = param_2->field_0x27_w;
            if (*(int *)(lVar8 + (long)*(int *)(param_1 + 1) * 0x30 + 0x28) <= iVar9)
            goto LAB_7100001044;
            if ((double)*(float *)&param_2->field_0x10 <= *(double *)&param_2->field_0x18_w) {
              uVar13 = 0x249;
              goto LAB_7100001028;
            }
LAB_7100000f2c:
            param_2->field_0x20_w = (char)iVar9;
            param_2->field_0x21_w = (char)((uint)iVar9 >> 8);
            param_2->field_0x22_w = (char)((uint)iVar9 >> 0x10);
            param_2->field_0x23_w = (char)((uint)iVar9 >> 0x18);
            uVar10 = *(uint *)(lVar8 + (long)*(int *)(param_1 + 1) * 0x30 + 0x28);
            if (iVar9 + 1 < (int)uVar10) {
              uVar10 = iVar9 + 1;
            }
            param_2->field_0x24_w = (char)uVar10;
            param_2->field_0x25_w = (char)(uVar10 >> 8);
            param_2->field_0x26_w = (char)(uVar10 >> 0x10);
            param_2->field_0x27_w = (char)(uVar10 >> 0x18);
            if (*(char *)((long)&param_1[1].field_0x4_r + 1) != '\0') goto LAB_7100000ebc;
          } while( true );
        }
        goto LAB_7100000d7c;
      }
      uVar13 = 0x22e;
      goto LAB_7100001028;
    }
  } while( true );
LAB_7100001044:
  param_2->field_0x20_w = 0;
  param_2->field_0x21_w = 0;
  param_2->field_0x22_w = 0;
  param_2->field_0x23_w = 0;
  param_2->field_0x24_w = 1;
  param_2->field_0x25_w = 0;
  param_2->field_0x26_w = 0;
  param_2->field_0x27_w = 0;
  if ((char)param_1[1].field_0x4_r != '\0') goto LAB_7100000d7c;
  goto LAB_7100000ec4;
}



long FUN_710000119c(long param_1)

{
  long lVar1;
  
  (*(code *)*DAT_7103a64a58)(*(undefined8 *)(param_1 + 0x2f0),0x5afa00,1);
  lVar1 = (*(code *)*DAT_7103a64b20)(*(undefined8 *)(param_1 + 0x2f0));
  return (ulong)(*(char *)(lVar1 + 0x5afa00) != ':') << 1;
}



ulong FUN_7100001200(undefined8 *param_1)

{
  uint uVar1;
  uint uVar2;
  ulong uVar3;
  undefined4 in_w6;
  undefined4 in_w7;
  undefined8 in_stack_00000000;
  
  uVar3 = (**(code **)(*(long *)*param_1 + 0x20))();
  if ((int)uVar3 != 0) {
    return uVar3;
  }
  uVar1 = (**(code **)(*(long *)*param_1 + 0x30))((long *)*param_1,in_w6,in_stack_00000000,in_w7);
  uVar2 = (**(code **)(*(long *)*param_1 + 0x50))();
  uVar1 = (uVar1 ^ 0xffffffff) & 1;
  if (uVar2 != 0) {
    uVar1 = uVar2;
  }
  return (ulong)uVar1;
}



void FUN_71000012b4(auto_FUN_71000012b4_param_1 *param_1,undefined4 param_2,undefined8 param_3,
                   int param_4,uint param_5)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  int iVar5;
  undefined8 *puVar6;
  long lVar7;
  undefined8 uVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  long lVar12;
  
  switch(param_2) {
  case 0:
    lVar9 = *(long *)param_1;
    iVar5 = *(int *)&param_1->field_0x8;
    uVar8 = *(undefined8 *)&param_1->field_0x10;
    lVar10 = lVar9 + 0x90800;
    if ((param_4 < 1) && (0 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[7].field_0x2,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x56fa00,(long)iVar5);
      (*(code *)*puVar6)(param_3,5,2,lVar9,6);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x52f800,300);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 2) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar2 = lVar9 + 0x8f800;
    if ((param_4 < 2) && (1 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0xc,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x1000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 3) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar11 = lVar9 + 0x94800;
    if ((param_4 < 3) && (2 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[1].field_0x4A_r + 4),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x1000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x400);
      (*(code *)*DAT_7103a68da8)(param_3,0x40,1,1);
      if (param_5 < 4) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0x94c00;
    if ((param_4 < 4) && (3 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0x4,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x400);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x100);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 5) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 5) && (4 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x1e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x94d00,0x800);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x100);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x700,0x1200);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x1900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 6) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 6) && (5 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x2e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x94d00,0x800);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x95500,0x2000);
      (*(code *)*DAT_7103a68da8)(param_3,4,1,1);
      if (param_5 < 7) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 7) && (6 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x28,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x97500,0x1c00);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x95500,0x2000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x1a00,0x7e00);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x9800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 8) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 8) && (7 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x38,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x97500,0x1c00);
      (*(code *)*puVar6)(param_3,5,2,lVar11,0x400);
      (*(code *)*DAT_7103a68da8)(param_3,4,1,1);
      if (param_5 < 9) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 9) && (8 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x30,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x96c00,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x2000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x9900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x12900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 10) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 10) && (9 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x1e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x96c00,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x98c00,0x8000);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0xb) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xb) && (10 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x38,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xa0c00,0x7000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x98c00,0x8000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x12a00,0x7e00);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x1a800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xc) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xc) && (0xb < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x18,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xa0c00,0x7000);
      (*(code *)*puVar6)(param_3,5,2,lVar2,0x1000);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0xd) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xd) && (0xc < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x40,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9c800,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x8000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x1a900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x23900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xe) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0xa4800;
    if ((param_4 < 0xe) && (0xd < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x26,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9c800,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x20000);
      (*(code *)*DAT_7103a68da8)(param_3,0x80,1,1);
      if (param_5 < 0xf) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xf) && (0xe < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x48,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xc4800,0x1c000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x23a00,0x7e00);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x2b800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x10) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x10) && (0xf < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x20,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xc4800,0x1c000);
      (*(code *)*puVar6)(param_3,5,2,lVar10,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,0x80,1,1);
      if (param_5 < 0x11) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar12 = lVar9 + 0xb3800;
    lVar3 = lVar9 + 0xb4800;
    if ((param_4 < 0x11) && (0x10 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar3,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x2b900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x34900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x12) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x12) && (0x11 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar3,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x34a00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x3da00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x13) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x13) && (0x12 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar3,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x3db00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x46b00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x14) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x14) && (0x13 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar3,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x46c00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x4fc00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x15) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x15) && (0x14 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar3,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x4fd00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x58d00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x16) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x16) && (0x15 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0x6,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar3,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x58e00,0x4800);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x5d600,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0x17) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x17) && (0x16 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0xe,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x10000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x5d700,0x2400);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x5fb00,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x18) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x18) && (0x17 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x18,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar3,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x5fc00,0x14400);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x74000,0x240);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x19) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0x144800;
    if ((param_4 < 0x19) && (0x18 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0x2c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar3,0x90000);
      (*(code *)*DAT_7103a68da8)(param_3,0x480,1,1);
      if (param_5 < 0x1a) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar3 = lVar9 + 0x1dc800;
    lVar4 = lVar9 + 0x200800;
    lVar1 = lVar9 + 0x74700;
    if ((param_4 < 0x1a) && (0x19 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x3e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar4,0x51000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x90000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74300,0x240);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x74600,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x90,1,1);
      if (param_5 < 0x1b) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1b) && (0x1a < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x16,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x90000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74b00,0x2400);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x76f00,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,0x18,1,1);
      if (param_5 < 0x1c) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1c) && (0x1b < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[2].field_0x44,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x251800,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x90000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x77000,0x900);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x77900,0x10);
      (*(code *)*DAT_7103a68da8)(param_3,0x18,1,1);
      if (param_5 < 0x1d) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1d) && (0x1c < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0xc,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x4840);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,10,1,1);
      if (param_5 < 0x1e) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1e) && (0x1d < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0x46,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar3,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x4840);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x100,0x510);
      (*(code *)*DAT_7103a68da8)(param_3,0x40,1,1);
      if (param_5 < 0x1f) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar10 = lVar9 + 0x98800;
    if ((param_4 < 0x1f) && (0x1e < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x46,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x144000);
      (*(code *)*puVar6)(param_3,5,1,lVar3,0x24000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 0x20) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x20) && (0x1f < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0x14,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar3,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x251800,0x24000);
      (*(code *)*DAT_7103a68da8)(param_3,0x90,1,1);
      if (param_5 < 0x21) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar11 = lVar9 + 0x2cf800;
    if ((param_4 < 0x21) && (0x20 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[6].field_0x4A_r + 2),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x51000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x144000);
      (*(code *)*puVar6)(param_3,5,2,lVar4,0x51000);
      (*(code *)*DAT_7103a68da8)(param_3,0x144,1,1);
      if (param_5 < 0x22) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0x329800;
    if ((param_4 < 0x22) && (0x21 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x26,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x14400);
      (*(code *)*puVar6)(param_3,5,1,lVar3,0x24000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x77a00,0x240);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x77d00,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x23) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x23) && (0x22 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0x14,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x9000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x51000);
      (*(code *)*puVar6)(param_3,5,2,lVar1,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x60,1,1);
      if (param_5 < 0x24) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x24) && (0x23 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x10,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x320800,0x9000);
      (*(code *)*puVar6)(param_3,5,1,lVar4,0x51000);
      (*(code *)*puVar6)(param_3,5,2,lVar1,0x24);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x74a00,4);
      (*(code *)*puVar6)(param_3,5,4,lVar2,0x9000);
      (*(code *)*DAT_7103a68da8)(param_3,0x30,1,1);
      if (param_5 < 0x25) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x25) && (0x24 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x16,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar3,0xf3000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x51000);
      (*(code *)*puVar6)(param_3,5,2,lVar10,0x144000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 0x26) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x26) && (0x25 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[3].field_0x3a,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x1b000);
      (*(code *)*puVar6)(param_3,5,1,lVar3,0xf3000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74800,0x6c);
      (*(code *)*DAT_7103a68da8)(param_3,0x120,1,1);
      if (param_5 < 0x27) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x27) && (0x26 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x42,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar12,0x1b000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x1b000);
      (*(code *)*puVar6)(param_3,5,2,lVar2,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x74900,4);
      (*(code *)*DAT_7103a68da8)(param_3,0x6c,1,1);
      if (param_5 < 0x28) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x28) && (0x27 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x28,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar12,0x1b000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x320800,0x9000);
      (*(code *)*DAT_7103a68da8)(param_3,0x90,1,1);
      if (param_5 < 0x29) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x29) && (0x28 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[5].field_0x4A_r + 4),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar12,0x25840);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x24000);
      (*(code *)*DAT_7103a68da8)(param_3,0x97,1,1);
      if (param_5 < 0x2a) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar10 = lVar9 + 0xd9100;
    if ((param_4 < 0x2a) && (0x29 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0x1c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x51000);
      (*(code *)*puVar6)(param_3,5,1,lVar12,0x25840);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x100,0x510);
      (*(code *)*DAT_7103a68da8)(param_3,0x18,1,1);
      if (param_5 < 0x2b) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x2b) && (0x2a < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0x34,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x14400);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x51000);
      (*(code *)*puVar6)(param_3,5,2,lVar7,0x14400);
      (*(code *)*DAT_7103a68da8)(param_3,0x29,1,1);
      if (param_5 < 0x2c) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar11 = lVar9 + 0xa3c00;
    if ((param_4 < 0x2c) && (0x2b < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0x24,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x2400);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x14400);
      (*(code *)*puVar6)(param_3,5,2,lVar1,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x18,1,1);
      if (param_5 < 0x2d) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x2d) && (0x2c < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1->field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x12a100,0x3cc00);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x14400);
      (*(code *)*puVar6)(param_3,5,2,lVar10,0x51000);
      (*(code *)*DAT_7103a68da8)(param_3,0x7a,1,1);
      if (param_5 < 0x2e) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x2e) && (0x2d < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[3].field_0xa,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x6c00);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x12a100,0x3cc00);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74800,0x6c);
      (*(code *)*DAT_7103a68da8)(param_3,0x48,1,1);
      if (param_5 < 0x2f) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x2f) && (0x2e < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x12,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x96400,0x6c00);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x6c00);
      (*(code *)*puVar6)(param_3,5,2,lVar11,0x2400);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x77e00,4);
      (*(code *)*DAT_7103a68da8)(param_3,0xe,1,1);
      if (param_5 < 0x30) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x30) && (0x2f < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,param_1[3].field_0x4A_r,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9d000,0x2400);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x14400);
      (*(code *)*puVar6)(param_3,5,2,lVar1,0x24);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x77f00,4);
      (*(code *)*puVar6)(param_3,5,4,lVar11,0x2400);
      (*(code *)*DAT_7103a68da8)(param_3,0x18,1,1);
      if (param_5 < 0x31) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if (0x30 < param_4) {
      return;
    }
    if ((int)param_5 < 0x31) {
      return;
    }
    (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x48,0x20);
    (*DAT_7103ff42c8)(param_3,5,0,uVar8,(long)((double)iVar5 * 1.5 * 1.5));
    (*DAT_7103ff42c8)(param_3,5,1,lVar9 + 0x96400,0x6c00);
    (*DAT_7103ff42c8)(param_3,5,2,lVar9 + 0x9d000,0x2400);
    (*DAT_7103ff42c8)(param_3,5,3,lVar9,6);
    (*(code *)*DAT_7103a68da8)(param_3,0x2a,1,1);
    if (param_5 < 0x32) {
      return;
    }
    goto LAB_710000b1ec;
  case 1:
    lVar9 = *(long *)param_1;
    iVar5 = *(int *)&param_1->field_0x8;
    uVar8 = *(undefined8 *)&param_1->field_0x10;
    lVar10 = lVar9 + 0x90800;
    if ((param_4 < 1) && (0 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[7].field_0x2,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x56fa00,(long)iVar5);
      (*(code *)*puVar6)(param_3,5,2,lVar9,6);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x52f800,300);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 2) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar2 = lVar9 + 0x8f800;
    if ((param_4 < 2) && (1 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0xc,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x1000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 3) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 3) && (2 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0xc,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x94800,0x4840);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,10,1,1);
      if (param_5 < 4) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar11 = lVar9 + 0x99100;
    if ((param_4 < 4) && (3 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[1].field_0x4A_r + 4),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x1000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x400);
      (*(code *)*DAT_7103a68da8)(param_3,0x40,1,1);
      if (param_5 < 5) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0x99500;
    if ((param_4 < 5) && (4 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0x4,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x400);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x100);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 6) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 6) && (5 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x1e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x99600,0x800);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x100);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x700,0x1200);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x1900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 7) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 7) && (6 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x2e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x99600,0x800);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x99e00,0x2000);
      (*(code *)*DAT_7103a68da8)(param_3,4,1,1);
      if (param_5 < 8) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 8) && (7 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x28,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9be00,0x1c00);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x99e00,0x2000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x1a00,0x7e00);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x9800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 9) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 9) && (8 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x38,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9be00,0x1c00);
      (*(code *)*puVar6)(param_3,5,2,lVar11,0x400);
      (*(code *)*DAT_7103a68da8)(param_3,4,1,1);
      if (param_5 < 10) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 10) && (9 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x30,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9b500,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x2000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x9900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x12900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xb) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xb) && (10 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x1e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9b500,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9d500,0x8000);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0xc) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xc) && (0xb < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x38,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xa5500,0x7000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9d500,0x8000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x12a00,0x7e00);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x1a800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xd) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xd) && (0xc < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x18,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xa5500,0x7000);
      (*(code *)*puVar6)(param_3,5,2,lVar2,0x1000);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0xe) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xe) && (0xd < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x40,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xa1100,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x8000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x1a900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x23900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xf) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0xa9100;
    if ((param_4 < 0xf) && (0xe < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x26,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xa1100,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x20000);
      (*(code *)*DAT_7103a68da8)(param_3,0x80,1,1);
      if (param_5 < 0x10) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x10) && (0xf < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x48,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xc9100,0x1c000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x23a00,0x7e00);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x2b800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x11) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x11) && (0x10 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x20,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xc9100,0x1c000);
      (*(code *)*puVar6)(param_3,5,2,lVar10,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,0x80,1,1);
      if (param_5 < 0x12) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar10 = lVar9 + 0xb9100;
    if ((param_4 < 0x12) && (0x11 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x2b900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x34900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x13) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x13) && (0x12 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x34a00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x3da00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x14) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x14) && (0x13 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x3db00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x46b00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x15) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x15) && (0x14 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x46c00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x4fc00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x16) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x16) && (0x15 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x4fd00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x58d00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x17) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x17) && (0x16 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x6,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x58e00,0x4800);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x5d600,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0x18) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x18) && (0x17 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0xe,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x10000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x78000,0x2400);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x7a400,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x19) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x19) && (0x18 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[2].field_0x4A_r + 2),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x40000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x7a500,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x83500,0x100);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x1a) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0xf9100;
    if ((param_4 < 0x1a) && (0x19 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0x1c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x40000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x40000);
      (*(code *)*DAT_7103a68da8)(param_3,0x200,1,1);
      if (param_5 < 0x1b) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1b) && (0x1a < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x20,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x40000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x40000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x83c00,0x2400);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x86000,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x1c) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1c) && (0x1b < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x2,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x139100,0x100000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x40000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x86100,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x8f100,0x100);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 0x1d) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1d) && (0x1c < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[6].field_0x24,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x239100,0x100000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x139100,0x100000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 0x1e) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar10 = lVar9 + 0x14d100;
    if ((param_4 < 0x1e) && (0x1d < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x2e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x40000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x83600,0x240);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x83900,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 0x1f) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1f) && (0x1e < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x46,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x94800,0x4840);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x100,0x510);
      (*(code *)*DAT_7103a68da8)(param_3,0x40,1,1);
      if (param_5 < 0x20) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0xbd100;
    if ((param_4 < 0x20) && (0x1f < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[1].field_0x36,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x24000);
      (*(code *)*DAT_7103a68da8)(param_3,0x480,1,1);
      if (param_5 < 0x21) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x21) && (0x20 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[6].field_0x3c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x90000);
      (*(code *)*puVar6)(param_3,5,2,lVar10,0x24000);
      (*(code *)*DAT_7103a68da8)(param_3,0x120,1,1);
      if (param_5 < 0x22) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar11 = lVar9 + 0xb3800;
    lVar12 = lVar9 + 0x74700;
    if ((param_4 < 0x22) && (0x21 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[2].field_0x2c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x24000);
      (*(code *)*puVar6)(param_3,5,2,lVar12,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 0x23) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x23) && (0x22 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[1].field_0x6,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x171100,0x6c000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x24000);
      (*(code *)*puVar6)(param_3,5,2,lVar7,0x90000);
      (*(code *)*DAT_7103a68da8)(param_3,0x360,1,1);
      if (param_5 < 0x24) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x24) && (0x23 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)(param_1 + 4),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xa7800,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x24000);
      (*(code *)*puVar6)(param_3,5,2,lVar12,0x24);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x83b00,4);
      (*(code *)*puVar6)(param_3,5,4,lVar11,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 0x25) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x25) && (0x24 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x1a,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0xc000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x171100,0x6c000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74800,0x6c);
      (*(code *)*DAT_7103a68da8)(param_3,0x60,1,1);
      if (param_5 < 0x26) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x26) && (0x25 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x22,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9b800,0xc000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0xc000);
      (*(code *)*puVar6)(param_3,5,2,lVar11,0x4000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x83a00,4);
      (*(code *)*DAT_7103a68da8)(param_3,0x30,1,1);
      if (param_5 < 0x27) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x27) && (0x26 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1->field_0x30,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xab800,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9b800,0xc000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0xa7800,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 0x28) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x28) && (0x27 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[6].field_0x4,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x11040);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xab800,0x10000);
      (*(code *)*DAT_7103a68da8)(param_3,0x23,1,1);
      if (param_5 < 0x29) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x29) && (0x28 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[2].field_0x34,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x3ff800,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x11040);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x100,0x510);
      (*(code *)*DAT_7103a68da8)(param_3,0x40,1,1);
      if (param_5 < 0x2a) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar10 = lVar9 + 0x36f800;
    if ((param_4 < 0x2a) && (0x29 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x36,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x239100,0x100000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x8f200,0x240);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x8f500,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 0x2b) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar11 = lVar9 + 0x12f800;
    if ((param_4 < 0x2b) && (0x2a < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[1].field_0x3e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x240000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x3ff800,0x90000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 0x2c) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x2c) && (0x2b < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[6].field_0x44,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x240000);
      (*(code *)*puVar6)(param_3,5,2,lVar10,0x90000);
      (*(code *)*DAT_7103a68da8)(param_3,0x480,1,1);
      if (param_5 < 0x2d) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0x11f800;
    if ((param_4 < 0x2d) && (0x2c < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[2].field_0x3c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x90000);
      (*(code *)*puVar6)(param_3,5,2,lVar12,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 0x2e) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x2e) && (0x2d < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x8,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x51f800,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x90000);
      (*(code *)*puVar6)(param_3,5,2,lVar12,0x24);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x8f700,4);
      (*(code *)*puVar6)(param_3,5,4,lVar7,0x10000);
      (*(code *)*DAT_7103a68da8)(param_3,0x80,1,1);
      if (param_5 < 0x2f) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x2f) && (0x2e < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[1].field_0xe,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x1b0000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x90000);
      (*(code *)*puVar6)(param_3,5,2,lVar11,0x240000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 0x30) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x30) && (0x2f < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x2a,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x30000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x1b0000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74800,0x6c);
      (*(code *)*DAT_7103a68da8)(param_3,0xc0,1,1);
      if (param_5 < 0x31) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x31) && (0x30 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x32,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xbf800,0x30000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x30000);
      (*(code *)*puVar6)(param_3,5,2,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x8f600,4);
      (*(code *)*DAT_7103a68da8)(param_3,0xc0,1,1);
      if (param_5 < 0x32) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if (0x31 < param_4) {
      return;
    }
    if ((int)param_5 < 0x32) {
      return;
    }
    (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x40,0x20);
    puVar6 = DAT_7103a68da0;
    (*(code *)*DAT_7103a68da0)(param_3,5,0,uVar8,(long)(iVar5 << 4));
    (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xbf800,0x30000);
    (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x51f800,0x10000);
    (*(code *)*puVar6)(param_3,5,3,lVar9,6);
    (*(code *)*DAT_7103a68da8)(param_3,0x70,1,1);
    if (param_5 < 0x33) {
      return;
    }
    goto LAB_710000b1ec;
  case 2:
    lVar9 = *(long *)param_1;
    uVar8 = *(undefined8 *)&param_1->field_0x10;
    iVar5 = *(int *)&param_1->field_0x8;
    lVar10 = lVar9 + 0x90800;
    if ((param_4 < 1) && (0 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[7].field_0x2,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x56fa00,(long)iVar5);
      (*(code *)*puVar6)(param_3,5,2,lVar9,6);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x52f800,300);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 2) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar2 = lVar9 + 0x8f800;
    if ((param_4 < 2) && (1 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0xc,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x1000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 3) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 3) && (2 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0xc,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x94800,0x4840);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,10,1,1);
      if (param_5 < 4) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar11 = lVar9 + 0x99100;
    if ((param_4 < 4) && (3 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[1].field_0x4A_r + 4),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x1000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x400);
      (*(code *)*DAT_7103a68da8)(param_3,0x40,1,1);
      if (param_5 < 5) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0x99500;
    if ((param_4 < 5) && (4 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0x4,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x400);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x100);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 6) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 6) && (5 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0x1e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x99600,0x800);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x100);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x700,0x1200);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x1900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 7) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 7) && (6 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x2e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x99600,0x800);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x99e00,0x2000);
      (*(code *)*DAT_7103a68da8)(param_3,4,1,1);
      if (param_5 < 8) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 8) && (7 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x28,0x20);
      (*DAT_7103ff42c8)(param_3,5,0,lVar9 + 0x9be00,0x1c00);
      (*DAT_7103ff42c8)(param_3,5,1,lVar9 + 0x99e00,0x2000);
      (*DAT_7103ff42c8)(param_3,5,2,lVar9 + 0x1a00,0x7e00);
      (*DAT_7103ff42c8)(param_3,5,3,lVar9 + 0x9800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 9) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 9) && (8 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x38,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9be00,0x1c00);
      (*(code *)*puVar6)(param_3,5,2,lVar11,0x400);
      (*(code *)*DAT_7103a68da8)(param_3,4,1,1);
      if (param_5 < 10) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 10) && (9 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x30,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9b500,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x2000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x9900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x12900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xb) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xb) && (10 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x1e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9b500,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9d500,0x8000);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0xc) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xc) && (0xb < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x38,0x20);
      (*DAT_7103ff42c8)(param_3,5,0,lVar9 + 0xa5500,0x7000);
      (*DAT_7103ff42c8)(param_3,5,1,lVar9 + 0x9d500,0x8000);
      (*DAT_7103ff42c8)(param_3,5,2,lVar9 + 0x12a00,0x7e00);
      (*DAT_7103ff42c8)(param_3,5,3,lVar9 + 0x1a800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xd) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xd) && (0xc < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x18,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xa5500,0x7000);
      (*(code *)*puVar6)(param_3,5,2,lVar2,0x1000);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0xe) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xe) && (0xd < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x40,0x20);
      (*DAT_7103ff42c8)(param_3,5,0,lVar9 + 0xa1100,0x8000);
      (*DAT_7103ff42c8)(param_3,5,1,lVar11,0x8000);
      (*DAT_7103ff42c8)(param_3,5,2,lVar9 + 0x1a900,0x9000);
      (*DAT_7103ff42c8)(param_3,5,3,lVar9 + 0x23900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xf) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0xa9100;
    if ((param_4 < 0xf) && (0xe < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x26,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xa1100,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x20000);
      (*(code *)*DAT_7103a68da8)(param_3,0x80,1,1);
      if (param_5 < 0x10) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x10) && (0xf < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x48,0x20);
      (*DAT_7103ff42c8)(param_3,5,0,lVar9 + 0xc9100,0x1c000);
      (*DAT_7103ff42c8)(param_3,5,1,lVar7,0x20000);
      (*DAT_7103ff42c8)(param_3,5,2,lVar9 + 0x23a00,0x7e00);
      (*DAT_7103ff42c8)(param_3,5,3,lVar9 + 0x2b800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x11) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x11) && (0x10 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x20,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xc9100,0x1c000);
      (*(code *)*puVar6)(param_3,5,2,lVar10,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,0x80,1,1);
      if (param_5 < 0x12) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar10 = lVar9 + 0xb9100;
    if ((param_4 < 0x12) && (0x11 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x2b900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x34900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x13) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x13) && (0x12 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x34a00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x3da00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x14) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x14) && (0x13 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x3db00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x46b00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x15) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x15) && (0x14 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x46c00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x4fc00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x16) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x16) && (0x15 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x4fd00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x58d00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x17) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x17) && (0x16 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x6,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x58e00,0x4800);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x5d600,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0x18) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x18) && (0x17 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0xe,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x10000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x78000,0x2400);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x7a400,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x19) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x19) && (0x18 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[2].field_0x4A_r + 2),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x40000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x7a500,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x83500,0x100);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x1a) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1a) && (0x19 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0x1c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xf9100,0x40000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x40000);
      (*(code *)*DAT_7103a68da8)(param_3,0x200,1,1);
      if (param_5 < 0x1b) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1b) && (0x1a < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0x46,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x94800,0x4840);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x100,0x510);
      (*(code *)*DAT_7103a68da8)(param_3,0x40,1,1);
      if (param_5 < 0x1c) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar10 = lVar9 + 0xbd100;
    if ((param_4 < 0x1c) && (0x1b < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x2e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xf9100,0x40000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x83600,0x240);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x83900,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 0x1d) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0xfb800;
    if ((param_4 < 0x1d) && (0x1c < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x36,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x24000);
      (*(code *)*DAT_7103a68da8)(param_3,0x480,1,1);
      if (param_5 < 0x1e) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar11 = lVar9 + 0x18b800;
    if ((param_4 < 0x1e) && (0x1d < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0x3c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x90000);
      (*(code *)*puVar6)(param_3,5,2,lVar10,0x24000);
      (*(code *)*DAT_7103a68da8)(param_3,0x120,1,1);
      if (param_5 < 0x1f) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar12 = lVar9 + 0x1af800;
    if ((param_4 < 0x1f) && (0x1e < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0x2c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar12,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x24000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74700,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 0x20) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x20) && (0x1f < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)(param_1 + 4),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x1b3800,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x24000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74700,0x24);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x83b00,4);
      (*(code *)*puVar6)(param_3,5,4,lVar12,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 0x21) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x21) && (0x20 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x6,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x6c000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x24000);
      (*(code *)*puVar6)(param_3,5,2,lVar7,0x90000);
      (*(code *)*DAT_7103a68da8)(param_3,0x360,1,1);
      if (param_5 < 0x22) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x22) && (0x21 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x1a,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0xc000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x6c000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74800,0x6c);
      (*(code *)*DAT_7103a68da8)(param_3,0x60,1,1);
      if (param_5 < 0x23) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x23) && (0x22 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x22,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0xc000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0xc000);
      (*(code *)*puVar6)(param_3,5,2,lVar12,0x4000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x83a00,4);
      (*(code *)*DAT_7103a68da8)(param_3,0x30,1,1);
      if (param_5 < 0x24) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x24) && (0x23 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x30,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9b800,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0xc000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x1b3800,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 0x25) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if (0x24 < param_4) {
      return;
    }
    if ((int)param_5 < 0x25) {
      return;
    }
    (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[7].field_0x12,0x20);
    puVar6 = DAT_7103a68da0;
    (*(code *)*DAT_7103a68da0)(param_3,5,0,uVar8,(long)(iVar5 << 2));
    (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9b800,0x10000);
    (*(code *)*puVar6)(param_3,5,2,lVar9,6);
    (*(code *)*DAT_7103a68da8)(param_3,0x38,1,1);
    break;
  case 3:
    lVar9 = *(long *)param_1;
    iVar5 = *(int *)&param_1->field_0x8;
    uVar8 = *(undefined8 *)&param_1->field_0x10;
    lVar10 = lVar9 + 0x90800;
    if ((param_4 < 1) && (0 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[7].field_0x2,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x56fa00,(long)iVar5);
      (*(code *)*puVar6)(param_3,5,2,lVar9,6);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x52f800,300);
      (*(code *)*DAT_7103a68da8)(param_3,0x20,1,1);
      if (param_5 < 2) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 2) && (1 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0xc,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x94800,0x4840);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,10,1,1);
      if (param_5 < 3) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar2 = lVar9 + 0x8f800;
    if ((param_4 < 3) && (2 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0xc,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x4000);
      (*(code *)*puVar6)(param_3,5,1,lVar2,0x1000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 4) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar11 = lVar9 + 0x99100;
    if ((param_4 < 4) && (3 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[1].field_0x4A_r + 4),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x1000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x400);
      (*(code *)*DAT_7103a68da8)(param_3,0x40,1,1);
      if (param_5 < 5) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0x99500;
    if ((param_4 < 5) && (4 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0x4,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x400);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x100);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 6) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 6) && (5 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0x1e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x99600,0x800);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x100);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x700,0x1200);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x1900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 7) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 7) && (6 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x2e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x99600,0x800);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x99e00,0x2000);
      (*(code *)*DAT_7103a68da8)(param_3,4,1,1);
      if (param_5 < 8) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 8) && (7 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x28,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9be00,0x1c00);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x99e00,0x2000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x1a00,0x7e00);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x9800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 9) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 9) && (8 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x38,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9be00,0x1c00);
      (*(code *)*puVar6)(param_3,5,2,lVar11,0x400);
      (*(code *)*DAT_7103a68da8)(param_3,4,1,1);
      if (param_5 < 10) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 10) && (9 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x30,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9b500,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x2000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x9900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x12900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xb) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xb) && (10 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x1e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x9b500,0x2000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9d500,0x8000);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0xc) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xc) && (0xb < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x38,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xa5500,0x7000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x9d500,0x8000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x12a00,0x7e00);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x1a800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xd) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xd) && (0xc < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x18,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xa5500,0x7000);
      (*(code *)*puVar6)(param_3,5,2,lVar2,0x1000);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0xe) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0xe) && (0xd < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x40,0x20);
      (*DAT_7103ff42c8)(param_3,5,0,lVar9 + 0xa1100,0x8000);
      (*DAT_7103ff42c8)(param_3,5,1,lVar11,0x8000);
      (*DAT_7103ff42c8)(param_3,5,2,lVar9 + 0x1a900,0x9000);
      (*DAT_7103ff42c8)(param_3,5,3,lVar9 + 0x23900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0xf) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0xa9100;
    if ((param_4 < 0xf) && (0xe < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x26,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xa1100,0x8000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x20000);
      (*(code *)*DAT_7103a68da8)(param_3,0x80,1,1);
      if (param_5 < 0x10) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x10) && (0xf < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x48,0x20);
      (*DAT_7103ff42c8)(param_3,5,0,lVar9 + 0xc9100,0x1c000);
      (*DAT_7103ff42c8)(param_3,5,1,lVar7,0x20000);
      (*DAT_7103ff42c8)(param_3,5,2,lVar9 + 0x23a00,0x7e00);
      (*DAT_7103ff42c8)(param_3,5,3,lVar9 + 0x2b800,0x70);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x11) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x11) && (0x10 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x20,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xc9100,0x1c000);
      (*(code *)*puVar6)(param_3,5,2,lVar10,0x4000);
      (*(code *)*DAT_7103a68da8)(param_3,0x80,1,1);
      if (param_5 < 0x12) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar10 = lVar9 + 0xb9100;
    if ((param_4 < 0x12) && (0x11 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x2b900,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x34900,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x13) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x13) && (0x12 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x34a00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x3da00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x14) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x14) && (0x13 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x3db00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x46b00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x15) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x15) && (0x14 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x46c00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x4fc00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x16) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x16) && (0x15 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[4].field_0x4A_r + 6),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x4fd00,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x58d00,0x80);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x17) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x17) && (0x16 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0x6,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x20000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x58e00,0x4800);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x5d600,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,8,1,1);
      if (param_5 < 0x18) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x18) && (0x17 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[5].field_0xe,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x10000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x5d700,0x2400);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x5fb00,0x40);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x19) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x19) && (0x18 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[4].field_0x18,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x10000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x5fc00,0x14400);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x74000,0x240);
      (*(code *)*DAT_7103a68da8)(param_3,0x10,1,1);
      if (param_5 < 0x1a) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1a) && (0x19 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[6].field_0x2c,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x149100,0x90000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x90000);
      (*(code *)*DAT_7103a68da8)(param_3,0x480,1,1);
      if (param_5 < 0x1b) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar10 = lVar9 + 0x1dc800;
    lVar11 = lVar9 + 0x200800;
    if ((param_4 < 0x1b) && (0x1a < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x3e,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar11,0x51000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x149100,0x90000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74300,0x240);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x74600,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x90,1,1);
      if (param_5 < 0x1c) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1c) && (0x1b < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[5].field_0x46,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0x94800,0x4840);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x100,0x510);
      (*(code *)*DAT_7103a68da8)(param_3,0x40,1,1);
      if (param_5 < 0x1d) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar7 = lVar9 + 0x98800;
    if ((param_4 < 0x1d) && (0x1c < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x46,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x144000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0x24000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 0x1e) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    lVar12 = lVar9 + 0x2cf800;
    if ((param_4 < 0x1e) && (0x1d < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)((long)&param_1[6].field_0x4A_r + 2),0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar12,0x51000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x144000);
      (*(code *)*puVar6)(param_3,5,2,lVar11,0x51000);
      (*(code *)*DAT_7103a68da8)(param_3,0x144,1,1);
      if (param_5 < 0x1f) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x1f) && (0x1e < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[2].field_0x14,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x9000);
      (*(code *)*puVar6)(param_3,5,1,lVar12,0x51000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74700,0x24);
      (*(code *)*DAT_7103a68da8)(param_3,0x60,1,1);
      if (param_5 < 0x20) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x20) && (0x1f < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[4].field_0x10,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0x320800,0x9000);
      (*(code *)*puVar6)(param_3,5,1,lVar11,0x51000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74700,0x24);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x74a00,4);
      (*(code *)*puVar6)(param_3,5,4,lVar2,0x9000);
      (*(code *)*DAT_7103a68da8)(param_3,0x30,1,1);
      if (param_5 < 0x21) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x21) && (0x20 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[1].field_0x16,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar10,0xf3000);
      (*(code *)*puVar6)(param_3,5,1,lVar12,0x51000);
      (*(code *)*puVar6)(param_3,5,2,lVar7,0x144000);
      (*(code *)*DAT_7103a68da8)(param_3,0x100,1,1);
      if (param_5 < 0x22) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x22) && (0x21 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x3a,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar7,0x1b000);
      (*(code *)*puVar6)(param_3,5,1,lVar10,0xf3000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x74800,0x6c);
      (*(code *)*DAT_7103a68da8)(param_3,0x120,1,1);
      if (param_5 < 0x23) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x23) && (0x22 < (int)param_5)) {
      (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[3].field_0x42,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar9 + 0xb3800,0x1b000);
      (*(code *)*puVar6)(param_3,5,1,lVar7,0x1b000);
      (*(code *)*puVar6)(param_3,5,2,lVar2,0x9000);
      (*(code *)*puVar6)(param_3,5,3,lVar9 + 0x74900,4);
      (*(code *)*DAT_7103a68da8)(param_3,0x6c,1,1);
      if (param_5 < 0x24) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if ((param_4 < 0x24) && (0x23 < (int)param_5)) {
      (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1->field_0x28,0x20);
      puVar6 = DAT_7103a68da0;
      (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar2,0x24000);
      (*(code *)*puVar6)(param_3,5,1,lVar9 + 0xb3800,0x1b000);
      (*(code *)*puVar6)(param_3,5,2,lVar9 + 0x320800,0x9000);
      (*(code *)*DAT_7103a68da8)(param_3,0x90,1,1);
      if (param_5 < 0x25) {
        return;
      }
      (*(code *)*DAT_7103a633f0)(param_3,1);
    }
    if (0x24 < param_4) {
      return;
    }
    if ((int)param_5 < 0x25) {
      return;
    }
    (*(code *)*DAT_7103a678d0)(param_3,*(undefined8 *)&param_1[7].field_0xa,0x20);
    (*DAT_7103ff42c8)(param_3,5,0,uVar8,(long)(iVar5 * 9));
    (*DAT_7103ff42c8)(param_3,5,1,lVar2,0x24000);
    (*DAT_7103ff42c8)(param_3,5,2,lVar9,6);
    (*(code *)*DAT_7103a68da8)(param_3,0x54,1,1);
    break;
  default:
    goto switchD_7100001308_default;
  }
  if (param_5 < 0x26) {
switchD_7100001308_default:
    return;
  }
LAB_710000b1ec:
                    // WARNING: Could not recover jumptable at 0x00710000b21c. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a633f0)(param_3,1);
  return;
}



void FUN_710000b240(auto_FUN_710000b240_param_1 *param_1,undefined4 param_2,undefined8 param_3,
                   int param_4)

{
  int iVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  long lVar4;
  code *pcVar5;
  undefined8 uVar6;
  
  switch(param_2) {
  case 0:
    lVar4 = *(long *)param_1;
    iVar1 = *(int *)((long)&param_1->field_0x2_r + 6);
    uVar6 = *(undefined8 *)&param_1->field_0x10;
    (*DAT_7103ff4288)(param_3,*(undefined8 *)((long)&param_1[7].field_0x2_r + 4),0x20);
    puVar2 = DAT_7103a68da0;
    (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar4 + 0x52fa00,(long)iVar1);
    (*(code *)*puVar2)(param_3,5,1,lVar4 + 0x52f800 + (long)param_4 * 0x96,0x96);
    (*(code *)*puVar2)(param_3,5,2,uVar6,(long)((double)iVar1 * 1.5 * 1.5));
    pcVar5 = (code *)*DAT_7103a68da8;
    if (iVar1 == 0x10000) {
      uVar6 = 0xc;
      uVar3 = 0xc;
      goto LAB_710000b5b4;
    }
    break;
  case 1:
    lVar4 = *(long *)param_1;
    iVar1 = *(int *)((long)&param_1->field_0x2_r + 6);
    uVar6 = *(undefined8 *)&param_1->field_0x10;
    (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[7].field_0x16,0x20);
    puVar2 = DAT_7103a68da0;
    (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar4 + 0x52fa00,(long)iVar1);
    (*(code *)*puVar2)(param_3,5,1,lVar4 + 0x52f800 + (long)param_4 * 0x96,0x96);
    (*(code *)*puVar2)(param_3,5,2,uVar6,(long)iVar1 << 4);
    pcVar5 = (code *)*DAT_7103a68da8;
    if (iVar1 != 0x10000) {
      uVar6 = 0x40;
      uVar3 = 0x40;
      goto LAB_710000b5b4;
    }
    goto LAB_710000b588;
  case 2:
    lVar4 = *(long *)param_1;
    iVar1 = *(int *)((long)&param_1->field_0x2_r + 6);
    uVar6 = *(undefined8 *)&param_1->field_0x10;
    (*DAT_7103ff4288)(param_3,*(undefined8 *)&param_1[7].field_0xe,0x20);
    puVar2 = DAT_7103a68da0;
    (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar4 + 0x52fa00,(long)iVar1);
    (*(code *)*puVar2)(param_3,5,1,lVar4 + 0x52f800 + (long)param_4 * 0x96,0x96);
    (*(code *)*puVar2)(param_3,5,2,uVar6,(long)iVar1 << 2);
    pcVar5 = (code *)*DAT_7103a68da8;
    if (iVar1 == 0x10000) {
      uVar6 = 0x10;
      uVar3 = 0x10;
      goto LAB_710000b5b4;
    }
LAB_710000b588:
    uVar6 = 0x20;
    uVar3 = 0x20;
    goto LAB_710000b5b4;
  case 3:
    lVar4 = *(long *)param_1;
    iVar1 = *(int *)((long)&param_1->field_0x2_r + 6);
    uVar6 = *(undefined8 *)&param_1->field_0x10;
    (*DAT_7103ff4288)(param_3,*(undefined8 *)((long)&param_1[6].field_0x4E_r + 6),0x20);
    puVar2 = DAT_7103a68da0;
    (*(code *)*DAT_7103a68da0)(param_3,5,0,lVar4 + 0x52fa00,(long)iVar1);
    (*(code *)*puVar2)(param_3,5,1,lVar4 + 0x52f800 + (long)param_4 * 0x96,0x96);
    (*(code *)*puVar2)(param_3,5,2,uVar6,(long)(iVar1 * 9));
    pcVar5 = (code *)*DAT_7103a68da8;
    if (iVar1 != 0x10000) {
      uVar6 = 0x30;
      uVar3 = 0x30;
      goto LAB_710000b5b4;
    }
    break;
  default:
    return;
  }
  uVar6 = 0x18;
  uVar3 = 0x18;
LAB_710000b5b4:
  (*pcVar5)(param_3,uVar6,uVar3,1);
                    // WARNING: Could not recover jumptable at 0x00710000b5e4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a633f0)(param_3,1);
  return;
}



void FUN_710000b5e8(auto_FUN_710000b5e8_param_1 *param_1,undefined8 param_2)

{
  int iVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  long lVar5;
  
  lVar5 = *(long *)param_1;
  iVar1 = *(int *)((long)&param_1->field_0x1_r + 7);
  (*DAT_7103ff4288)(param_2,*(undefined8 *)&param_1[7].field_0x19,0x20);
  puVar2 = DAT_7103a68da0;
  (*(code *)*DAT_7103a68da0)(param_2,5,0,lVar5 + 0x52fa00,(long)iVar1);
  (*(code *)*puVar2)(param_2,5,1,lVar5 + 0x56fa00,(long)iVar1);
  (*(code *)*puVar2)(param_2,5,2,lVar5 + 0x52f800,300);
  (*(code *)*puVar2)(param_2,5,3,lVar5 + 4,2);
  if (iVar1 == 0x10000) {
    uVar3 = 6;
    uVar4 = 6;
  }
  else {
    uVar3 = 0xc;
    uVar4 = 0xc;
  }
  (*(code *)*DAT_7103a68da8)(param_2,uVar3,uVar4,1);
                    // WARNING: Could not recover jumptable at 0x00710000b718. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a633f0)(param_2,1);
  return;
}



void FUN_710000b71c(auto_FUN_710000b71c_param_1 *param_1,undefined8 param_2)

{
  undefined8 *puVar1;
  long lVar2;
  undefined8 uVar3;
  
  lVar2 = *(long *)param_1;
  uVar3 = *(undefined8 *)&param_1->field_0x10;
  (*(code *)*DAT_7103a678d0)(param_2,*(undefined8 *)&param_1[7].field_0x18,0x20);
  puVar1 = DAT_7103a68da0;
  (*(code *)*DAT_7103a68da0)(param_2,5,0,uVar3,0x400000);
  (*(code *)*puVar1)(param_2,5,1,lVar2 + 6,2);
  (*(code *)*DAT_7103a68da8)(param_2,0x100,4,4);
                    // WARNING: Could not recover jumptable at 0x00710000b7e4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a633f0)(param_2,1);
  return;
}



void FUN_710000b7e8(auto_FUN_710000b7e8_param_1 *param_1,undefined8 param_2)

{
  undefined8 *puVar1;
  long lVar2;
  
  lVar2 = *(long *)param_1;
  (*DAT_7103ff4288)(param_2,*(undefined8 *)&param_1[7].field_0x18,0x20);
  puVar1 = DAT_7103a68da0;
  (*(code *)*DAT_7103a68da0)(param_2,5,0,lVar2 + 0x56fa00,0x40000);
  (*(code *)*puVar1)(param_2,5,1,lVar2 + 6,2);
  (*(code *)*DAT_7103a68da8)(param_2,0x100,1,1);
                    // WARNING: Could not recover jumptable at 0x00710000b8b4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a633f0)(param_2,1);
  return;
}



void FUN_710000b8b8(auto_FUN_710000b8b8_param_1 *param_1,undefined8 param_2,
                   auto_FUN_710000b8b8_param_3 *param_3)

{
  *(undefined8 *)param_1 = param_2;
  *(undefined8 *)&param_1->field_0x18 = *(undefined8 *)param_3;
  *(undefined8 *)&param_1->field_0x20 = *(undefined8 *)&param_3->field_0x8;
  *(undefined8 *)&param_1->field_0x28 = *(undefined8 *)&param_3->field_0x10;
  *(undefined8 *)&param_1->field_0x30 = *(undefined8 *)&param_3->field_0x18;
  *(undefined8 *)&param_1->field_0x38 = *(undefined8 *)&param_3->field_0x20;
  *(undefined8 *)&param_1->field_0x40 = *(undefined8 *)&param_3->field_0x28;
  *(undefined8 *)&param_1->field_0x48 = *(undefined8 *)&param_3->field_0x30;
  *(undefined8 *)&param_1->field_0x50 = *(undefined8 *)&param_3->field_0x38;
  *(undefined8 *)((long)&param_1->field_0x53_w + 5) = *(undefined8 *)&param_3->field_0x40;
  *(undefined8 *)&param_1[1].field_0x5 = *(undefined8 *)&param_3->field_0x48;
  *(qword *)&param_1[1].field_0xd = param_3->field_0x50_r;
  *(undefined8 *)&param_1[1].field_0x15 = *(undefined8 *)(param_3 + 1);
  *(undefined8 *)&param_1[1].field_0x1d = *(undefined8 *)&param_3[1].field_0x8;
  *(undefined8 *)&param_1[1].field_0x25 = *(undefined8 *)&param_3[1].field_0x10;
  *(undefined8 *)&param_1[1].field_0x2d = *(undefined8 *)&param_3[1].field_0x18;
  *(undefined8 *)&param_1[1].field_0x35 = *(undefined8 *)&param_3[1].field_0x20;
  *(undefined8 *)&param_1[1].field_0x3d = *(undefined8 *)&param_3[1].field_0x28;
  *(undefined8 *)&param_1[1].field_0x45 = *(undefined8 *)&param_3[1].field_0x30;
  *(undefined8 *)&param_1[1].field_0x4d = *(undefined8 *)&param_3[1].field_0x38;
  *(undefined8 *)((long)&param_1[1].field_0x53_w + 2) = *(undefined8 *)&param_3[1].field_0x40;
  *(undefined8 *)&param_1[2].field_0x2 = *(undefined8 *)&param_3[1].field_0x48;
  *(qword *)&param_1[2].field_0xa = param_3[1].field_0x50_r;
  *(undefined8 *)&param_1[2].field_0x12 = *(undefined8 *)(param_3 + 2);
  *(undefined8 *)&param_1[2].field_0x1a = *(undefined8 *)&param_3[2].field_0x8;
  *(undefined8 *)&param_1[2].field_0x22 = *(undefined8 *)&param_3[2].field_0x10;
  *(undefined8 *)&param_1[2].field_0x2a = *(undefined8 *)&param_3[2].field_0x18;
  *(undefined8 *)&param_1[2].field_0x32 = *(undefined8 *)&param_3[2].field_0x20;
  *(undefined8 *)&param_1[2].field_0x3a = *(undefined8 *)&param_3[2].field_0x28;
  *(undefined8 *)&param_1[2].field_0x42 = *(undefined8 *)&param_3[2].field_0x30;
  *(undefined8 *)&param_1[2].field_0x4a = *(undefined8 *)&param_3[2].field_0x38;
  *(undefined8 *)&param_1[2].field_0x52 = *(undefined8 *)&param_3[2].field_0x40;
  *(undefined8 *)((long)&param_1[2].field_0x53_w + 7) = *(undefined8 *)&param_3[2].field_0x48;
  *(qword *)&param_1[3].field_0x7 = param_3[2].field_0x50_r;
  *(undefined8 *)&param_1[3].field_0xf = *(undefined8 *)(param_3 + 3);
  *(undefined8 *)&param_1[3].field_0x17 = *(undefined8 *)&param_3[3].field_0x8;
  *(undefined8 *)&param_1[3].field_0x1f = *(undefined8 *)&param_3[3].field_0x10;
  *(undefined8 *)&param_1[3].field_0x27 = *(undefined8 *)&param_3[3].field_0x18;
  *(undefined8 *)&param_1[3].field_0x2f = *(undefined8 *)&param_3[3].field_0x20;
  *(undefined8 *)&param_1[3].field_0x37 = *(undefined8 *)&param_3[3].field_0x28;
  *(undefined8 *)&param_1[3].field_0x3f = *(undefined8 *)&param_3[3].field_0x30;
  *(undefined8 *)&param_1[3].field_0x47 = *(undefined8 *)&param_3[3].field_0x38;
  *(undefined8 *)&param_1[3].field_0x4f = *(undefined8 *)&param_3[3].field_0x40;
  *(undefined8 *)((long)&param_1[3].field_0x53_w + 4) = *(undefined8 *)&param_3[3].field_0x48;
  *(qword *)&param_1[4].field_0x4 = param_3[3].field_0x50_r;
  *(undefined8 *)&param_1[4].field_0xc = *(undefined8 *)(param_3 + 4);
  *(undefined8 *)&param_1[4].field_0x14 = *(undefined8 *)&param_3[4].field_0x8;
  *(undefined8 *)&param_1[4].field_0x1c = *(undefined8 *)&param_3[4].field_0x10;
  *(undefined8 *)&param_1[4].field_0x24 = *(undefined8 *)&param_3[4].field_0x18;
  *(undefined8 *)&param_1[4].field_0x2c = *(undefined8 *)&param_3[4].field_0x20;
  *(undefined8 *)&param_1[4].field_0x34 = *(undefined8 *)&param_3[4].field_0x28;
  *(undefined8 *)&param_1[4].field_0x3c = *(undefined8 *)&param_3[4].field_0x30;
  *(undefined8 *)&param_1[4].field_0x44 = *(undefined8 *)&param_3[4].field_0x38;
  *(undefined8 *)&param_1[4].field_0x4c = *(undefined8 *)&param_3[4].field_0x40;
  *(undefined8 *)((long)&param_1[4].field_0x53_w + 1) = *(undefined8 *)&param_3[4].field_0x48;
  *(qword *)&param_1[5].field_0x1 = param_3[4].field_0x50_r;
  *(undefined8 *)&param_1[5].field_0x9 = *(undefined8 *)(param_3 + 5);
  *(undefined8 *)&param_1[5].field_0x11 = *(undefined8 *)&param_3[5].field_0x8;
  *(undefined8 *)&param_1[5].field_0x19 = *(undefined8 *)&param_3[5].field_0x10;
  *(undefined8 *)&param_1[5].field_0x21 = *(undefined8 *)&param_3[5].field_0x18;
  *(undefined8 *)&param_1[5].field_0x29 = *(undefined8 *)&param_3[5].field_0x20;
  *(undefined8 *)&param_1[5].field_0x31 = *(undefined8 *)&param_3[5].field_0x28;
  *(undefined8 *)&param_1[5].field_0x39 = *(undefined8 *)&param_3[5].field_0x30;
  *(undefined8 *)&param_1[5].field_0x41 = *(undefined8 *)&param_3[5].field_0x38;
  *(undefined8 *)&param_1[5].field_0x49 = *(undefined8 *)&param_3[5].field_0x40;
  *(undefined8 *)&param_1[5].field_0x51 = *(undefined8 *)&param_3[5].field_0x48;
  *(qword *)((long)&param_1[5].field_0x53_w + 6) = param_3[5].field_0x50_r;
  *(undefined8 *)&param_1[6].field_0x6 = *(undefined8 *)(param_3 + 6);
  *(undefined8 *)&param_1[6].field_0xe = *(undefined8 *)&param_3[6].field_0x8;
  *(undefined8 *)&param_1[6].field_0x16 = *(undefined8 *)&param_3[6].field_0x10;
  *(undefined8 *)&param_1[6].field_0x1e = *(undefined8 *)&param_3[6].field_0x18;
  *(undefined8 *)&param_1[6].field_0x26 = *(undefined8 *)&param_3[6].field_0x20;
  *(undefined8 *)&param_1[6].field_0x2e = *(undefined8 *)&param_3[6].field_0x28;
  *(undefined8 *)&param_1[6].field_0x36 = *(undefined8 *)&param_3[6].field_0x30;
  *(undefined8 *)&param_1[6].field_0x3e = *(undefined8 *)&param_3[6].field_0x38;
  *(undefined8 *)&param_1[6].field_0x46 = *(undefined8 *)&param_3[6].field_0x40;
  *(undefined8 *)&param_1[6].field_0x4e = *(undefined8 *)&param_3[6].field_0x48;
  *(qword *)((long)&param_1[6].field_0x53_w + 3) = param_3[6].field_0x50_r;
  *(undefined8 *)&param_1[7].field_0x3 = *(undefined8 *)(param_3 + 7);
  *(undefined8 *)&param_1[7].field_0xb = *(undefined8 *)&param_3[7].field_0x8;
  *(undefined8 *)&param_1[7].field_0x13 = *(undefined8 *)&param_3[7].field_0x10;
  *(undefined8 *)&param_1[7].field_0x1b = *(undefined8 *)&param_3[7].field_0x18;
  return;
}



void FUN_710000bb48(auto_FUN_710000bb48_param_1 *param_1,undefined8 param_2,int param_3,
                   undefined8 param_4)

{
  undefined8 *puVar1;
  long lVar2;
  undefined4 uVar3;
  
  lVar2 = *(long *)param_1;
  *(int *)&param_1->field_0x8 = param_3;
  (*DAT_7103ff4288)(param_4,*(undefined8 *)&param_1[7].field_0x17,0x20);
  puVar1 = DAT_7103a68da0;
  (*(code *)*DAT_7103a68da0)(param_4,5,0,param_2,(long)param_3);
  (*(code *)*puVar1)(param_4,5,1,lVar2 + 0x52fa00,(long)param_3);
  uVar3 = 0x80;
  if (param_3 != 0x10000) {
    uVar3 = 0x200;
  }
  (*(code *)*DAT_7103a68da8)(param_4,uVar3,1,1);
                    // WARNING: Could not recover jumptable at 0x00710000bc34. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a633f0)(param_4,1);
  return;
}



void FUN_710000bc38(long param_1,undefined8 param_2)

{
  *(undefined8 *)(param_1 + 0x10) = param_2;
  return;
}



void FUN_710000bc40(auto_FUN_710000bc40_param_1 *param_1,undefined8 param_2)

{
  long lVar1;
  
  lVar1 = *(long *)param_1;
  (*DAT_7103ff4288)(param_2,*(undefined8 *)&param_1[7].field_0x1a,0x20);
  (*(code *)*DAT_7103a68da0)(param_2,5,0,lVar1 + 0x52f800,300);
  (*(code *)*DAT_7103a68da8)(param_2,1,1,1);
                    // WARNING: Could not recover jumptable at 0x00710000bcd8. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a633f0)(param_2,1);
  return;
}



void FUN_710000bcdc(auto_FUN_710000bcdc_param_1 *param_1,undefined8 param_2,int param_3)

{
  undefined8 *puVar1;
  long lVar2;
  
  lVar2 = *(long *)param_1;
  (*DAT_7103ff4288)(param_2,*(undefined8 *)&param_1[7].field_0x1b,0x20);
  puVar1 = DAT_7103a68da0;
  (*(code *)*DAT_7103a68da0)(param_2,5,0,lVar2 + (long)param_3 * 0x96 + 0x52f800,0x96);
  (*(code *)*puVar1)(param_2,5,1,lVar2,8);
  (*(code *)*DAT_7103a68da8)(param_2,1,1,1);
                    // WARNING: Could not recover jumptable at 0x00710000bdac. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a633f0)(param_2,1);
  return;
}



undefined8 FUN_710000bdc0(void)

{
  undefined8 uVar1;
  undefined8 local_18;
  
  local_18 = 0;
  uVar1 = FUN_71000110b0(&local_18,1);
  if ((int)uVar1 != 0) {
    return 0xfffffffb;
  }
  FUN_710000e070();
  return 0;
}



uint FUN_710000be10(uint param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = ((uint)(param_1 >> (ulong)(0x1eU - (int)LZCOUNT(param_1) & 0x1f) == 3) -
          (int)LZCOUNT(param_1)) + 0x1f;
  uVar2 = ((uint)(param_2 >> (ulong)(0x1eU - (int)LZCOUNT(param_2) & 0x1f) == 3) -
          (int)LZCOUNT(param_2)) + 0x1f;
  if (uVar2 <= uVar1) {
    uVar2 = uVar1;
  }
  if (uVar2 == 0) {
    uVar2 = 1;
  }
  return uVar2;
}



undefined8
FUN_710000be60(long *param_1,ulong *param_2,uint param_3,uint param_4,uint param_5,int param_6,
              uint param_7)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  long lVar5;
  ulong uVar6;
  long lVar7;
  ulong uVar8;
  ulong uVar9;
  int iVar10;
  auto_FUN_7100010524_param_1 aaStack_100 [3];
  
  if (param_1 == (long *)0x0) {
    return 0xfffffffc;
  }
  if (param_2 == (ulong *)0x0) {
    return 0xfffffffc;
  }
  if (param_5 == 0) {
    return 0xfffffffc;
  }
  if ((param_5 != 1) && (param_7 == 1)) {
    return 0xfffffffc;
  }
  uVar1 = ((uint)(param_3 >> (ulong)(0x1eU - (int)LZCOUNT(param_3) & 0x1f) == 3) -
          (int)LZCOUNT(param_3)) + 0x1f;
  uVar2 = ((uint)(param_4 >> (ulong)(0x1eU - (int)LZCOUNT(param_4) & 0x1f) == 3) -
          (int)LZCOUNT(param_4)) + 0x1f;
  if (uVar2 <= uVar1) {
    uVar2 = uVar1;
  }
  if (uVar2 == 0) {
    uVar2 = 1;
  }
  if (0xe < uVar2) {
    uVar2 = 0xf;
  }
  if (uVar2 < param_5) {
    return 0xfffffffc;
  }
  uVar1 = param_6 - 1;
  if ((5 < (uVar1 & 0xff)) || ((0x3bU >> (ulong)(uVar1 & 0x1f) & 1) == 0)) {
    return 0xfffffffb;
  }
  if (3 < param_7) {
    return 0xfffffffc;
  }
  uVar6 = -((ulong)(uVar1 >> 7) & 1) & 0xfffffffffffff800 | ((ulong)uVar1 & 0xff) << 3;
  iVar10 = 0x10;
  lVar5 = 1;
  bVar4 = true;
  switch(param_7) {
  case 0:
    goto switchD_710000bf90_caseD_0;
  case 1:
    iVar10 = 0x10;
    bVar4 = true;
    lVar5 = 0x20;
    goto switchD_710000bf90_caseD_0;
  case 2:
    iVar10 = 0;
    break;
  case 3:
    iVar10 = 0x200;
  }
  bVar4 = false;
  lVar5 = 1;
switchD_710000bf90_caseD_0:
  if (param_5 == 1) {
    uVar8 = 0;
  }
  else {
    uVar2 = param_3 >> 1;
    uVar3 = param_4 >> 1;
    if (uVar2 == 0) {
      uVar2 = 1;
    }
    if (uVar3 == 0) {
      uVar3 = 1;
    }
    uVar8 = *(long *)(&DAT_71030b9808 + uVar6) * (ulong)(uVar3 * uVar2);
  }
  lVar7 = *(long *)(&DAT_71030b9838 + uVar6);
  uVar9 = uVar8;
  if ((!bVar4) &&
     (uVar9 = ((lVar5 + lVar7 * (ulong)(param_3 + 3 >> 2)) - 1 & -lVar5) * (ulong)(param_4 + 3 >> 2)
     , uVar9 <= uVar8)) {
    uVar9 = uVar8;
  }
  if ((param_4 & 3) != 0) {
    uVar6 = (ulong)param_3 * *(long *)(&DAT_71030b9808 + uVar6) * 4;
    if (uVar6 <= uVar9) {
      uVar6 = uVar9;
    }
    uVar9 = uVar6 + uVar9;
  }
  *param_2 = uVar9;
  if (bVar4) {
    uVar6 = (ulong)param_5;
    do {
      uVar1 = param_3 + 3;
      uVar2 = param_4 + 3;
      param_3 = param_3 >> 1;
      param_4 = param_4 >> 1;
      if (param_3 == 0) {
        param_3 = 1;
      }
      if (param_4 == 0) {
        param_4 = 1;
      }
      uVar6 = uVar6 - 1;
      *param_1 = (lVar5 + -1 + lVar7 * (ulong)(uVar1 >> 2) & -lVar5) * (ulong)(uVar2 >> 2);
      param_1 = param_1 + 1;
    } while (uVar6 != 0);
    return 0;
  }
  FUN_7100010524(aaStack_100,*(undefined4 *)(&DAT_71030b9868 + (long)(char)uVar1 * 4),iVar10,param_3
                 ,param_4,param_5);
  FUN_7100010bb0((long)aaStack_100,iVar10,0,(long)param_1);
  return 0;
}



undefined8
FUN_710000c0f0(undefined8 *param_1,undefined8 *param_2,ulong param_3,ulong param_4,ulong param_5,
              uint param_6,uint param_7,uint param_8,byte param_9,int param_10,int param_11,
              uint param_12)

{
  undefined8 *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  undefined8 *puVar7;
  bool bVar8;
  undefined8 uVar9;
  long lVar10;
  long lVar11;
  undefined8 uVar12;
  ulong uVar13;
  ulong uVar14;
  code *pcVar15;
  uint uVar16;
  undefined4 uVar17;
  uint uVar18;
  ulong unaff_x23;
  undefined8 *puVar19;
  undefined8 *puVar20;
  ulong uVar21;
  auto_FUN_7100010524_param_1 aaStack_148 [3];
  
  if (param_1 == (undefined8 *)0x0) {
    return 0xfffffffc;
  }
  if (param_4 == 0) {
    return 0xfffffffc;
  }
  if ((param_8 != 0) && (param_10 == 1)) {
    return 0xfffffffc;
  }
  uVar4 = param_9 - 1;
  if ((5 < (uVar4 & 0xff)) || ((0x3bU >> (ulong)(uVar4 & 0x1f) & 1) == 0)) {
    return 0xfffffffb;
  }
  uVar17 = 0x10;
  lVar10 = 1;
  bVar8 = true;
  switch(param_10) {
  case 0:
    break;
  case 1:
    uVar17 = 0x10;
    bVar8 = true;
    lVar10 = 0x20;
    break;
  case 2:
    uVar17 = 0;
    goto LAB_710000c1e0;
  case 3:
    uVar17 = 0x200;
LAB_710000c1e0:
    bVar8 = false;
    lVar10 = 1;
    break;
  default:
    return 0xfffffffc;
  }
  uVar2 = param_6 >> (ulong)(param_8 & 0x1f);
  if (uVar2 < 2) {
    uVar2 = 1;
  }
  uVar18 = param_7 >> (ulong)(param_8 & 0x1f);
  uVar13 = -((ulong)(uVar4 >> 7) & 1) & 0xfffffffffffff800 | ((ulong)uVar4 & 0xff) << 3;
  if (uVar18 < 2) {
    uVar18 = 1;
  }
  if (param_10 != 0) {
    if (param_2 == (undefined8 *)0x0) {
      return 0xfffffffc;
    }
    uVar14 = *(long *)(&DAT_71030b9838 + uVar13) * (ulong)((uVar2 + 3 >> 2) * (uVar18 + 3 >> 2));
    if (param_3 <= uVar14 && uVar14 - param_3 != 0) {
      return 0xfffffffc;
    }
  }
  uVar14 = -param_5;
  if (-1 < (long)param_5) {
    uVar14 = param_5;
  }
  if (0xe < param_8 && param_10 != 0) {
    return 0xfffffffc;
  }
  uVar13 = *(long *)(&DAT_71030b9808 + uVar13) * (ulong)uVar2;
  if (uVar14 < uVar13) {
    return 0xfffffffc;
  }
  iVar5 = param_9 - 1;
  if ((iVar5 == 0) && (0xff < param_12)) {
    return 0xfffffffc;
  }
  uVar9 = 0xfffffffb;
  switch(iVar5) {
  case 0:
    uVar16 = param_12 << 0x18 | 0xffffff;
    uVar9 = DAT_7103a68e48;
    if (param_11 != 2) {
      uVar9 = DAT_7103a68e58;
    }
    break;
  case 1:
    uVar16 = 0;
    uVar9 = DAT_7103a68e40;
    if (param_11 != 2) {
      uVar9 = DAT_7103a68e50;
    }
    break;
  default:
    goto switchD_710000c2b4_caseD_2;
  case 3:
    pcVar15 = FUN_710000ca60;
    uVar12 = DAT_7103a68de8;
    uVar9 = DAT_7103a68df0;
    goto LAB_710000c378;
  case 4:
    uVar16 = 0;
    uVar9 = DAT_7103a68dd8;
    if (param_11 != 2) {
      uVar9 = DAT_7103a68de0;
    }
    pcVar15 = (code *)&UNK_710000ce60;
    lVar11 = 8;
    goto LAB_710000c380;
  case 5:
    pcVar15 = FUN_710000d150;
    uVar12 = DAT_7103a68dc8;
    uVar9 = DAT_7103a68dd0;
LAB_710000c378:
    uVar16 = 0;
    if (param_11 != 2) {
      uVar9 = uVar12;
    }
    lVar11 = 0x10;
    goto LAB_710000c380;
  }
  pcVar15 = (code *)&UNK_710000c640;
  lVar11 = 8;
LAB_710000c380:
  uVar3 = uVar18 + 3 >> 2;
  uVar14 = (lVar10 + lVar11 * (ulong)(uVar2 + 3 >> 2)) - 1 & -lVar10;
  puVar1 = param_2;
  puVar7 = param_1;
  if (!bVar8) {
    puVar1 = (undefined8 *)((long)param_2 + uVar14 * uVar3);
    puVar7 = param_2;
  }
  uVar6 = uVar18 - 4;
  puVar20 = puVar7;
  if (-1 < (int)uVar6) {
    do {
      unaff_x23 = (ulong)uVar18;
      (*pcVar15)(puVar20,param_4,param_5,uVar9,uVar2,uVar16);
      uVar18 = uVar18 - 4;
      puVar20 = (undefined8 *)((long)puVar20 + uVar14);
      param_4 = param_4 + param_5 * 4;
    } while (3 < (int)uVar18);
    uVar18 = uVar6 & 3;
  }
  if (0 < (int)uVar18) {
    if ((long)((long)param_2 + (param_3 - (long)puVar1)) < (long)(uVar13 * 4)) {
      return 0xfffffffc;
    }
    uVar21 = 0;
    if (uVar18 != 1) {
      puVar19 = puVar1;
      do {
        thunk_EXT_FUN_02e95df0(puVar19,param_4,uVar13);
        thunk_EXT_FUN_02e95df0((undefined8 *)((long)puVar19 + uVar13),param_4 + param_5,uVar13);
        puVar19 = (undefined8 *)((long)puVar19 + uVar13 * 2);
        uVar21 = uVar21 + 2;
        param_4 = param_4 + param_5 + param_5;
      } while (((ulong)uVar18 & 0xfffffffe) != uVar21);
      unaff_x23 = param_4 - param_5;
    }
    if ((uVar18 & 1) != 0) {
      thunk_EXT_FUN_02e95df0((undefined8 *)((long)puVar1 + uVar13 * uVar21),param_4,uVar13);
      unaff_x23 = param_4;
    }
    thunk_EXT_FUN_02e95df0((undefined8 *)((long)puVar1 + uVar13 * uVar18),unaff_x23,uVar13);
    if (uVar18 + 1 < 4) {
      thunk_EXT_FUN_02e95df0((undefined8 *)((long)puVar1 + uVar13 * (uVar18 + 1)),unaff_x23,uVar13);
      if (uVar18 + 2 < 4) {
        thunk_EXT_FUN_02e95df0
                  ((undefined8 *)((long)puVar1 + uVar13 * (uVar18 + 2)),unaff_x23,uVar13);
        if ((uVar18 + 3 < 4) &&
           (thunk_EXT_FUN_02e95df0
                      ((undefined8 *)((long)puVar1 + uVar13 * (uVar18 + 3)),unaff_x23,uVar13),
           0xfffffffb < uVar18)) {
          thunk_EXT_FUN_02e95df0
                    ((undefined8 *)((long)puVar1 + uVar13 * (uVar18 + 4)),unaff_x23,uVar13);
        }
      }
    }
    (*pcVar15)(puVar20,puVar1,uVar13,uVar9,uVar2,uVar16);
  }
  if (!bVar8) {
    FUN_7100010524(aaStack_148,*(undefined4 *)(&DAT_71030b9868 + (long)(char)uVar4 * 4),uVar17,
                   param_6,param_7,param_8 + 1);
    FUN_7100010d8c((long)aaStack_148,param_8,puVar7,(ulong)(uVar3 * (int)uVar14),(long)param_1);
  }
  uVar9 = 0;
switchD_710000c2b4_caseD_2:
  return uVar9;
}



void FUN_710000ca60(long param_1,long param_2,long param_3,undefined *param_4,uint param_5)

{
  long lVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  undefined1 uVar4;
  undefined1 uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  undefined1 *puVar9;
  long lVar10;
  long lVar11;
  int iVar12;
  long lVar13;
  undefined8 local_90;
  undefined1 *local_88;
  undefined1 local_80 [16];
  undefined1 local_70 [16];
  undefined1 local_60 [16];
  undefined1 local_50 [16];
  long local_40;
  long local_38;
  
  uVar7 = param_5 - 4;
  local_40 = param_3;
  local_38 = param_2;
  if (-1 < (int)uVar7) {
    do {
      (*(code *)param_4)(param_1,&local_38,&local_40);
      param_5 = param_5 - 4;
      param_1 = param_1 + 0x10;
      param_2 = local_38 + 0x10;
      local_38 = param_2;
    } while (3 < (int)param_5);
    param_5 = uVar7 & 3;
  }
  if (0 < (int)param_5) {
    lVar11 = 0;
    local_38 = param_2;
    while( true ) {
      uVar5 = *(undefined1 *)(local_38 + lVar11);
      lVar13 = local_38 + lVar11;
      local_80[lVar11] = uVar5;
      uVar2 = *(undefined1 *)(lVar13 + 1);
      local_80[lVar11 + 1] = uVar2;
      uVar3 = *(undefined1 *)(lVar13 + 2);
      local_80[lVar11 + 2] = uVar3;
      uVar4 = *(undefined1 *)(lVar13 + 3);
      local_80[lVar11 + 3] = uVar4;
      if ((ulong)param_5 * 4 + -4 == lVar11) break;
      lVar11 = lVar11 + 4;
    }
    uVar7 = param_5;
    if (param_5 < 4) {
      uVar7 = 3;
    }
    iVar8 = uVar7 - param_5;
    puVar9 = local_80 + lVar11 + 4;
    uVar6 = param_5;
    if ((iVar8 + 1U & 1) != 0) {
      *puVar9 = uVar5;
      puVar9 = local_80 + lVar11 + 8;
      local_80[lVar11 + 5] = uVar2;
      local_80[lVar11 + 6] = uVar3;
      local_80[lVar11 + 7] = uVar4;
      uVar6 = param_5 + 1;
    }
    if (param_5 < 3) {
      iVar12 = (uVar7 - uVar6) + 1;
      do {
        *puVar9 = uVar5;
        iVar12 = iVar12 + -2;
        puVar9[1] = uVar2;
        puVar9[2] = uVar3;
        puVar9[3] = uVar4;
        puVar9[4] = uVar5;
        puVar9[5] = uVar2;
        puVar9[6] = uVar3;
        puVar9[7] = uVar4;
        puVar9 = puVar9 + 8;
      } while (iVar12 != 0);
    }
    lVar10 = (ulong)param_5 - 1;
    lVar11 = 0;
    local_38 = local_38 + local_40;
    lVar13 = lVar10;
    while( true ) {
      lVar1 = local_38;
      uVar5 = *(undefined1 *)(local_38 + lVar11);
      local_70[lVar11] = uVar5;
      lVar1 = lVar1 + lVar11;
      uVar2 = *(undefined1 *)(lVar1 + 1);
      local_70[lVar11 + 1] = uVar2;
      uVar3 = *(undefined1 *)(lVar1 + 2);
      local_70[lVar11 + 2] = uVar3;
      uVar4 = *(undefined1 *)(lVar1 + 3);
      local_70[lVar11 + 3] = uVar4;
      if (lVar13 == 0) break;
      lVar13 = lVar13 + -1;
      lVar11 = lVar11 + 4;
    }
    puVar9 = local_70 + lVar11 + 4;
    uVar6 = param_5;
    if ((iVar8 + 1U & 1) != 0) {
      *puVar9 = uVar5;
      puVar9 = local_70 + lVar11 + 8;
      local_70[lVar11 + 5] = uVar2;
      local_70[lVar11 + 6] = uVar3;
      local_70[lVar11 + 7] = uVar4;
      uVar6 = param_5 + 1;
    }
    if (param_5 < 3) {
      iVar12 = (uVar7 - uVar6) + 1;
      do {
        *puVar9 = uVar5;
        iVar12 = iVar12 + -2;
        puVar9[1] = uVar2;
        puVar9[2] = uVar3;
        puVar9[3] = uVar4;
        puVar9[4] = uVar5;
        puVar9[5] = uVar2;
        puVar9[6] = uVar3;
        puVar9[7] = uVar4;
        puVar9 = puVar9 + 8;
      } while (iVar12 != 0);
    }
    lVar11 = 0;
    local_38 = local_38 + local_40;
    lVar13 = lVar10;
    while( true ) {
      lVar1 = local_38;
      uVar5 = *(undefined1 *)(local_38 + lVar11);
      local_60[lVar11] = uVar5;
      lVar1 = lVar1 + lVar11;
      uVar2 = *(undefined1 *)(lVar1 + 1);
      local_60[lVar11 + 1] = uVar2;
      uVar3 = *(undefined1 *)(lVar1 + 2);
      local_60[lVar11 + 2] = uVar3;
      uVar4 = *(undefined1 *)(lVar1 + 3);
      local_60[lVar11 + 3] = uVar4;
      if (lVar13 == 0) break;
      lVar13 = lVar13 + -1;
      lVar11 = lVar11 + 4;
    }
    puVar9 = local_60 + lVar11 + 4;
    uVar6 = param_5;
    if ((iVar8 + 1U & 1) != 0) {
      *puVar9 = uVar5;
      puVar9 = local_60 + lVar11 + 8;
      local_60[lVar11 + 5] = uVar2;
      local_60[lVar11 + 6] = uVar3;
      local_60[lVar11 + 7] = uVar4;
      uVar6 = param_5 + 1;
    }
    if (param_5 < 3) {
      iVar12 = (uVar7 - uVar6) + 1;
      do {
        *puVar9 = uVar5;
        iVar12 = iVar12 + -2;
        puVar9[1] = uVar2;
        puVar9[2] = uVar3;
        puVar9[3] = uVar4;
        puVar9[4] = uVar5;
        puVar9[5] = uVar2;
        puVar9[6] = uVar3;
        puVar9[7] = uVar4;
        puVar9 = puVar9 + 8;
      } while (iVar12 != 0);
    }
    lVar11 = 0;
    local_38 = local_38 + local_40;
    while( true ) {
      lVar13 = local_38;
      uVar5 = *(undefined1 *)(local_38 + lVar11);
      local_50[lVar11] = uVar5;
      lVar13 = lVar13 + lVar11;
      uVar2 = *(undefined1 *)(lVar13 + 1);
      local_50[lVar11 + 1] = uVar2;
      uVar3 = *(undefined1 *)(lVar13 + 2);
      local_50[lVar11 + 2] = uVar3;
      uVar4 = *(undefined1 *)(lVar13 + 3);
      local_50[lVar11 + 3] = uVar4;
      if (lVar10 == 0) break;
      lVar10 = lVar10 + -1;
      lVar11 = lVar11 + 4;
    }
    puVar9 = local_50 + lVar11 + 4;
    uVar6 = param_5;
    if ((iVar8 + 1U & 1) != 0) {
      *puVar9 = uVar5;
      puVar9 = local_50 + lVar11 + 8;
      local_50[lVar11 + 5] = uVar2;
      local_50[lVar11 + 6] = uVar3;
      local_50[lVar11 + 7] = uVar4;
      uVar6 = param_5 + 1;
    }
    if (param_5 < 3) {
      iVar8 = (uVar7 - uVar6) + 1;
      do {
        *puVar9 = uVar5;
        iVar8 = iVar8 + -2;
        puVar9[1] = uVar2;
        puVar9[2] = uVar3;
        puVar9[3] = uVar4;
        puVar9[4] = uVar5;
        puVar9[5] = uVar2;
        puVar9[6] = uVar3;
        puVar9[7] = uVar4;
        puVar9 = puVar9 + 8;
      } while (iVar8 != 0);
    }
    local_38 = local_38 + local_40;
    local_88 = local_80;
    local_90 = 0x10;
    (*(code *)param_4)(param_1,&local_88,&local_90);
  }
  return;
}



void FUN_710000d150(long param_1,auto_FUN_710000d150_param_2 *param_2,long param_3,
                   undefined *param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  undefined1 uVar3;
  byte bVar4;
  uint uVar5;
  long lVar6;
  uint uVar7;
  long lVar8;
  long lVar9;
  undefined1 *puVar10;
  int iVar11;
  ulong uVar12;
  uint uVar13;
  ulong uVar14;
  undefined8 local_90;
  undefined1 *local_88;
  undefined1 local_80;
  byte local_7f;
  undefined1 local_7c [4];
  undefined1 local_78;
  byte local_77;
  undefined1 local_74 [4];
  undefined1 local_70;
  byte local_6f;
  undefined1 local_6c [4];
  undefined1 local_68;
  byte local_67;
  undefined1 local_64 [36];
  long local_40;
  auto_FUN_710000d150_local_38 *local_38;
  
  uVar14 = (ulong)param_5;
  local_40 = param_3;
  local_38 = (auto_FUN_710000d150_local_38 *)param_2;
  if (-1 < (int)(param_5 - 4)) {
    do {
      (*(code *)param_4)(param_1,&local_38,&local_40,0,0);
      uVar13 = (int)uVar14 - 4;
      uVar14 = (ulong)uVar13;
      param_1 = param_1 + 0x10;
      param_2 = (auto_FUN_710000d150_param_2 *)(local_38 + 4);
      local_38 = (auto_FUN_710000d150_local_38 *)param_2;
    } while (3 < (int)uVar13);
    uVar14 = (ulong)(param_5 - 4 & 3);
  }
  uVar13 = (uint)uVar14;
  if (0 < (int)uVar13) {
    local_80 = *(undefined1 *)param_2;
    local_7f = param_2->field_0x1_r;
    puVar10 = (undefined1 *)((ulong)&local_80 | 2);
    uVar3 = local_80;
    bVar4 = local_7f;
    if (uVar13 != 1) {
      lVar9 = uVar14 - 1;
      lVar6 = 0;
      do {
        lVar8 = lVar6;
        uVar3 = (&param_2[1].field_0x0)[lVar8];
        puVar10[lVar8] = uVar3;
        bVar4 = (&param_2[1].field_0x1_r)[lVar8];
        lVar9 = lVar9 + -1;
        (puVar10 + lVar8)[1] = bVar4;
        lVar6 = lVar8 + 2;
      } while (lVar9 != 0);
      puVar10 = local_7c + lVar8;
    }
    uVar7 = uVar13;
    if (uVar13 < 4) {
      uVar7 = 3;
    }
    uVar5 = uVar7 - uVar13;
    uVar1 = uVar13;
    local_38 = (auto_FUN_710000d150_local_38 *)param_2;
    uVar12 = uVar14;
    for (uVar2 = uVar5 + 1 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar10 = uVar3;
      uVar1 = (int)uVar12 + 1;
      uVar12 = (ulong)uVar1;
      puVar10[1] = bVar4;
      puVar10 = puVar10 + 2;
    }
    if (2 < uVar5) {
      iVar11 = (uVar7 - uVar1) + 1;
      do {
        *puVar10 = uVar3;
        iVar11 = iVar11 + -4;
        puVar10[1] = bVar4;
        puVar10[2] = uVar3;
        puVar10[3] = bVar4;
        puVar10[4] = uVar3;
        puVar10[5] = bVar4;
        puVar10[6] = uVar3;
        puVar10[7] = bVar4;
        puVar10 = puVar10 + 8;
      } while (iVar11 != 0);
    }
    local_38 = (auto_FUN_710000d150_local_38 *)(&local_38->field_0x0 + local_40);
    local_78 = *(undefined1 *)local_38;
    local_77 = local_38->field_0x1_r;
    uVar1 = uVar13;
    uVar12 = uVar14;
    if (uVar13 == 1) {
      uVar2 = uVar5 + 1 & 3;
      uVar3 = local_78;
      bVar4 = local_77;
      puVar10 = (undefined1 *)((ulong)&local_80 | 10);
    }
    else {
      lVar9 = uVar14 - 1;
      lVar6 = 0;
      do {
        lVar8 = lVar6;
        uVar3 = (&local_38[1].field_0x0)[lVar8];
        puVar10 = (undefined1 *)(((ulong)&local_80 | 10) + lVar8);
        *puVar10 = uVar3;
        bVar4 = (&local_38[1].field_0x1_r)[lVar8];
        lVar9 = lVar9 + -1;
        puVar10[1] = bVar4;
        lVar6 = lVar8 + 2;
      } while (lVar9 != 0);
      uVar2 = uVar5 + 1 & 3;
      puVar10 = local_74 + lVar8;
    }
    for (; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar10 = uVar3;
      uVar1 = (int)uVar12 + 1;
      uVar12 = (ulong)uVar1;
      puVar10[1] = bVar4;
      puVar10 = puVar10 + 2;
    }
    if (2 < uVar5) {
      iVar11 = (uVar7 - uVar1) + 1;
      do {
        *puVar10 = uVar3;
        iVar11 = iVar11 + -4;
        puVar10[1] = bVar4;
        puVar10[2] = uVar3;
        puVar10[3] = bVar4;
        puVar10[4] = uVar3;
        puVar10[5] = bVar4;
        puVar10[6] = uVar3;
        puVar10[7] = bVar4;
        puVar10 = puVar10 + 8;
      } while (iVar11 != 0);
    }
    local_38 = (auto_FUN_710000d150_local_38 *)(&local_38->field_0x0 + local_40);
    local_70 = *(undefined1 *)local_38;
    local_6f = local_38->field_0x1_r;
    uVar1 = uVar13;
    uVar12 = uVar14;
    if (uVar13 == 1) {
      uVar2 = uVar5 + 1 & 3;
      uVar3 = local_70;
      bVar4 = local_6f;
      puVar10 = (undefined1 *)((ulong)&local_80 | 0x12);
    }
    else {
      lVar9 = uVar14 - 1;
      lVar6 = 0;
      do {
        lVar8 = lVar6;
        uVar3 = (&local_38[1].field_0x0)[lVar8];
        puVar10 = (undefined1 *)(((ulong)&local_80 | 0x12) + lVar8);
        *puVar10 = uVar3;
        bVar4 = (&local_38[1].field_0x1_r)[lVar8];
        lVar9 = lVar9 + -1;
        puVar10[1] = bVar4;
        lVar6 = lVar8 + 2;
      } while (lVar9 != 0);
      uVar2 = uVar5 + 1 & 3;
      puVar10 = local_6c + lVar8;
    }
    for (; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar10 = uVar3;
      uVar1 = (int)uVar12 + 1;
      uVar12 = (ulong)uVar1;
      puVar10[1] = bVar4;
      puVar10 = puVar10 + 2;
    }
    if (2 < uVar5) {
      iVar11 = (uVar7 - uVar1) + 1;
      do {
        *puVar10 = uVar3;
        iVar11 = iVar11 + -4;
        puVar10[1] = bVar4;
        puVar10[2] = uVar3;
        puVar10[3] = bVar4;
        puVar10[4] = uVar3;
        puVar10[5] = bVar4;
        puVar10[6] = uVar3;
        puVar10[7] = bVar4;
        puVar10 = puVar10 + 8;
      } while (iVar11 != 0);
    }
    local_38 = (auto_FUN_710000d150_local_38 *)(&local_38->field_0x0 + local_40);
    local_68 = *(undefined1 *)local_38;
    local_67 = local_38->field_0x1_r;
    if (uVar13 == 1) {
      puVar10 = (undefined1 *)((ulong)&local_80 | 0x1a);
      uVar3 = local_68;
      bVar4 = local_67;
    }
    else {
      lVar9 = uVar14 - 1;
      lVar6 = 0;
      do {
        lVar8 = lVar6;
        uVar3 = (&local_38[1].field_0x0)[lVar8];
        puVar10 = (undefined1 *)(((ulong)&local_80 | 0x1a) + lVar8);
        *puVar10 = uVar3;
        bVar4 = (&local_38[1].field_0x1_r)[lVar8];
        lVar9 = lVar9 + -1;
        puVar10[1] = bVar4;
        lVar6 = lVar8 + 2;
      } while (lVar9 != 0);
      puVar10 = local_64 + lVar8;
    }
    for (uVar1 = uVar5 + 1 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar10 = uVar3;
      uVar13 = (int)uVar14 + 1;
      uVar14 = (ulong)uVar13;
      puVar10[1] = bVar4;
      puVar10 = puVar10 + 2;
    }
    if (2 < uVar5) {
      iVar11 = (uVar7 - uVar13) + 1;
      do {
        *puVar10 = uVar3;
        iVar11 = iVar11 + -4;
        puVar10[1] = bVar4;
        puVar10[2] = uVar3;
        puVar10[3] = bVar4;
        puVar10[4] = uVar3;
        puVar10[5] = bVar4;
        puVar10[6] = uVar3;
        puVar10[7] = bVar4;
        puVar10 = puVar10 + 8;
      } while (iVar11 != 0);
    }
    local_38 = (auto_FUN_710000d150_local_38 *)(&local_38->field_0x0 + local_40);
    local_88 = &local_80;
    local_90 = 8;
    (*(code *)param_4)(param_1,&local_88,&local_90,0,0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulong FUN_710000da30(uint *param_1,long param_2,ulong param_3,uint param_4)

{
  ulong *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined1 auVar7 [16];
  undefined1 auVar8 [16];
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  undefined1 auVar11 [16];
  short sVar12;
  short sVar13;
  short sVar14;
  short sVar15;
  short sVar16;
  int iVar17;
  short sVar18;
  undefined1 auVar19 [16];
  undefined1 auVar20 [16];
  undefined1 auVar21 [16];
  char cVar22;
  ushort uVar23;
  ulong uVar24;
  short sVar25;
  ushort uVar26;
  short sVar27;
  short sVar28;
  short sVar29;
  ulong uVar30;
  ulong uVar31;
  short sVar32;
  short sVar33;
  ushort uVar50;
  ushort uVar51;
  ushort uVar52;
  ushort uVar53;
  ushort uVar54;
  ushort uVar55;
  undefined1 auVar34 [16];
  undefined1 auVar35 [16];
  undefined1 auVar36 [16];
  ushort uVar56;
  byte bVar57;
  byte bVar74;
  byte bVar75;
  ushort uVar76;
  byte bVar77;
  byte bVar78;
  ushort uVar79;
  byte bVar80;
  byte bVar81;
  ushort uVar82;
  byte bVar83;
  byte bVar84;
  ushort uVar85;
  byte bVar86;
  byte bVar87;
  ushort uVar88;
  byte bVar89;
  byte bVar90;
  ushort uVar91;
  byte bVar92;
  byte bVar93;
  undefined1 auVar58 [16];
  undefined1 auVar59 [16];
  ushort uVar94;
  int iVar95;
  undefined1 auVar97 [16];
  undefined1 auVar98 [16];
  uint uVar96;
  undefined1 auVar99 [16];
  undefined1 auVar100 [16];
  undefined1 auVar101 [16];
  short sVar102;
  short sVar108;
  short sVar109;
  short sVar110;
  short sVar111;
  short sVar112;
  short sVar113;
  undefined1 auVar103 [16];
  undefined1 auVar104 [16];
  undefined1 auVar105 [16];
  undefined1 auVar106 [16];
  undefined1 auVar107 [16];
  short sVar114;
  short sVar118;
  short sVar119;
  short sVar120;
  short sVar121;
  short sVar122;
  short sVar123;
  undefined1 auVar115 [16];
  undefined1 auVar116 [16];
  undefined1 auVar117 [16];
  byte bVar124;
  short sVar125;
  byte bVar134;
  short sVar135;
  byte bVar136;
  short sVar137;
  byte bVar138;
  short sVar139;
  byte bVar140;
  short sVar141;
  short sVar142;
  short sVar143;
  short sVar144;
  undefined1 auVar132 [16];
  undefined1 auVar133 [16];
  byte bVar145;
  byte bVar154;
  byte bVar155;
  byte bVar156;
  byte bVar157;
  undefined1 auVar152 [16];
  undefined1 auVar153 [16];
  short sVar158;
  short sVar160;
  short sVar161;
  short sVar162;
  short sVar163;
  short sVar164;
  short sVar165;
  short sVar166;
  undefined1 auVar159 [16];
  byte bVar167;
  short sVar168;
  byte bVar177;
  short sVar178;
  byte bVar179;
  short sVar180;
  byte bVar181;
  short sVar182;
  byte bVar183;
  short sVar184;
  short sVar185;
  short sVar186;
  short sVar187;
  undefined1 auVar175 [16];
  undefined1 auVar176 [16];
  byte bVar188;
  byte bVar197;
  byte bVar198;
  byte bVar199;
  byte bVar200;
  short sVar201;
  undefined1 auVar195 [16];
  undefined1 auVar196 [16];
  undefined1 auVar202 [16];
  undefined1 auVar203 [16];
  undefined1 auVar204 [16];
  undefined1 auVar205 [16];
  undefined1 auVar206 [16];
  int iVar207;
  int iVar215;
  undefined1 auVar208 [16];
  undefined1 auVar209 [16];
  undefined1 auVar210 [16];
  undefined1 auVar212 [16];
  undefined1 auVar213 [16];
  undefined1 auVar214 [16];
  int iVar216;
  int iVar223;
  undefined1 auVar217 [16];
  undefined1 auVar218 [16];
  undefined1 auVar219 [16];
  undefined1 auVar221 [16];
  undefined1 auVar222 [16];
  undefined1 auVar224 [16];
  undefined1 auVar225 [16];
  undefined1 auVar226 [16];
  undefined1 auVar227 [16];
  undefined1 auVar228 [16];
  undefined1 uVar229;
  undefined1 uVar230;
  undefined1 uVar231;
  undefined1 uVar232;
  undefined1 uVar233;
  undefined1 uVar234;
  undefined1 uVar235;
  undefined1 uVar236;
  undefined1 uVar237;
  undefined1 uVar238;
  undefined1 uVar239;
  undefined1 uVar240;
  undefined1 uVar241;
  undefined1 uVar242;
  undefined1 uVar243;
  undefined1 uVar244;
  undefined1 uVar245;
  undefined1 uVar246;
  undefined1 uVar247;
  undefined1 uVar248;
  undefined1 uVar249;
  undefined1 uVar250;
  undefined1 uVar251;
  undefined1 uVar252;
  undefined1 uVar253;
  undefined1 uVar254;
  undefined1 uVar255;
  undefined1 uVar256;
  ulong local_20;
  undefined8 uStack_18;
  ulong uStack_10;
  undefined8 uStack_8;
  undefined1 auVar37 [16];
  undefined1 auVar38 [16];
  undefined1 auVar39 [16];
  undefined1 auVar40 [16];
  undefined1 auVar41 [16];
  undefined1 auVar42 [16];
  undefined1 auVar43 [16];
  undefined1 auVar44 [16];
  undefined1 auVar45 [16];
  undefined1 auVar46 [16];
  undefined1 auVar47 [16];
  undefined1 auVar48 [16];
  undefined1 auVar49 [16];
  undefined1 auVar60 [16];
  undefined1 auVar61 [16];
  undefined1 auVar62 [16];
  undefined1 auVar63 [16];
  undefined1 auVar64 [16];
  undefined1 auVar65 [16];
  undefined1 auVar66 [16];
  undefined1 auVar67 [16];
  undefined1 auVar68 [16];
  undefined1 auVar69 [16];
  undefined1 auVar70 [16];
  undefined1 auVar71 [16];
  undefined1 auVar72 [16];
  undefined1 auVar73 [16];
  undefined4 uVar126;
  undefined6 uVar127;
  undefined8 uVar128;
  undefined1 auVar129 [12];
  undefined1 auVar130 [14];
  undefined1 auVar131 [16];
  undefined4 uVar146;
  undefined6 uVar147;
  undefined8 uVar148;
  undefined1 auVar149 [12];
  undefined1 auVar150 [14];
  undefined1 auVar151 [16];
  undefined4 uVar169;
  undefined6 uVar170;
  undefined8 uVar171;
  undefined1 auVar172 [12];
  undefined1 auVar173 [14];
  undefined1 auVar174 [16];
  undefined4 uVar189;
  undefined6 uVar190;
  undefined8 uVar191;
  undefined1 auVar192 [12];
  undefined1 auVar193 [14];
  undefined1 auVar194 [16];
  undefined1 auVar211 [16];
  undefined1 auVar220 [16];
  
  uVar30 = ((ulong)*param_1 & 0xff) * 0x101010101010101;
  uVar31 = CONCAT44(*(undefined4 *)((long)param_1 + param_2),*param_1);
  uVar24 = CONCAT44(*(undefined4 *)((long)param_1 + param_2 * 3),
                    *(undefined4 *)((long)param_1 + param_2 * 2));
  if (uVar31 == uVar30 && uVar24 == uVar30) {
    return (ulong)(param_4 ^ (uint)param_3 ^ (uint)uVar30) & 0xffff;
  }
  uVar31 = uVar31 ^ param_3;
  uVar24 = uVar24 ^ param_3;
  auVar210._8_8_ = uVar24;
  auVar210._0_8_ = uVar31;
  bVar57 = (byte)uVar31;
  auVar35[0] = -(bVar57 == 0xff);
  bVar74 = (byte)(uVar31 >> 8);
  auVar35[1] = -(bVar74 == 0xff);
  bVar75 = (byte)(uVar31 >> 0x10);
  auVar35[2] = -(bVar75 == 0xff);
  bVar77 = (byte)(uVar31 >> 0x18);
  auVar35[3] = -(bVar77 == 0xff);
  bVar78 = (byte)(uVar31 >> 0x20);
  auVar35[4] = -(bVar78 == 0xff);
  bVar80 = (byte)(uVar31 >> 0x28);
  auVar35[5] = -(bVar80 == 0xff);
  bVar81 = (byte)(uVar31 >> 0x30);
  auVar35[6] = -(bVar81 == 0xff);
  bVar83 = (byte)(uVar31 >> 0x38);
  auVar35[7] = -(bVar83 == 0xff);
  bVar84 = (byte)uVar24;
  auVar35[8] = -(bVar84 == 0xff);
  bVar86 = (byte)(uVar24 >> 8);
  auVar35[9] = -(bVar86 == 0xff);
  bVar87 = (byte)(uVar24 >> 0x10);
  auVar35[10] = -(bVar87 == 0xff);
  bVar89 = (byte)(uVar24 >> 0x18);
  auVar35[0xb] = -(bVar89 == 0xff);
  bVar90 = (byte)(uVar24 >> 0x20);
  auVar35[0xc] = -(bVar90 == 0xff);
  bVar92 = (byte)(uVar24 >> 0x28);
  auVar35[0xd] = -(bVar92 == 0xff);
  bVar93 = (byte)(uVar24 >> 0x30);
  auVar35[0xe] = -(bVar93 == 0xff);
  auVar226[0xf] = (byte)(uVar24 >> 0x38);
  auVar35[0xf] = -(auVar226[0xf] == 0xff);
  auVar176[0] = bVar57 & ~auVar35[0];
  auVar176[1] = bVar74 & ~auVar35[1];
  auVar176[2] = bVar75 & ~auVar35[2];
  auVar176[3] = bVar77 & ~auVar35[3];
  auVar176[4] = bVar78 & ~auVar35[4];
  auVar176[5] = bVar80 & ~auVar35[5];
  auVar176[6] = bVar81 & ~auVar35[6];
  auVar176[7] = bVar83 & ~auVar35[7];
  auVar176[8] = bVar84 & ~auVar35[8];
  auVar176[9] = bVar86 & ~auVar35[9];
  auVar176[10] = bVar87 & ~auVar35[10];
  auVar176[0xb] = bVar89 & ~auVar35[0xb];
  auVar176[0xc] = bVar90 & ~auVar35[0xc];
  auVar176[0xd] = bVar92 & ~auVar35[0xd];
  auVar176[0xe] = bVar93 & ~auVar35[0xe];
  auVar176[0xf] = auVar226[0xf] & ~auVar35[0xf];
  auVar219._1_15_ = auVar176._1_15_;
  auVar219[0] = NEON_umaxv(auVar176,1);
  iVar95 = auVar219._0_4_;
  if (iVar95 == 0) {
    uVar30 = uVar31 & 0x101010101010101 | 0x606060606060606;
    uVar31 = uVar24 & 0x101010101010101 | 0x606060606060606;
    uVar24 = (uVar30 | uVar30 >> 5) & 0x3f003f003f003f;
    uVar31 = (uVar31 | uVar31 >> 5) & 0x3f003f003f003f;
    uVar24 = uVar24 | uVar24 >> 10;
    uVar31 = uVar31 | uVar31 >> 10;
    return (uVar24 >> 0x14 & 0xfff000 | uVar24 & 0xfff) << 0x10 |
           (ulong)((uint)(uVar31 >> 0x14) & 0xfff000 | (uint)uVar31 & 0xfff) << 0x28;
  }
  auVar97[0] = NEON_umaxv(auVar210,1);
  auVar97._1_15_ = auVar219._1_15_;
  auVar98[0] = NEON_uminv(auVar210,1);
  auVar98._1_15_ = auVar219._1_15_;
  uVar96 = auVar98._0_4_;
  iVar6 = auVar97._0_4_ - uVar96;
  auVar213._1_15_ = auVar35._1_15_;
  auVar46._13_3_ = auVar35._13_3_;
  auVar222._11_5_ = auVar35._11_5_;
  auVar43._9_7_ = auVar35._9_7_;
  auVar41._7_9_ = auVar35._7_9_;
  auVar39._5_11_ = auVar35._5_11_;
  auVar37._3_13_ = auVar35._3_13_;
  if (iVar6 < 8) {
    if (0xf7 < uVar96) {
      uVar96 = 0xf8;
    }
    cVar22 = (char)uVar96;
    auVar34[0] = bVar57 - cVar22;
    auVar34[1] = bVar74 - cVar22;
    auVar34[2] = bVar75 - cVar22;
    auVar34[3] = bVar77 - cVar22;
    auVar34[4] = bVar78 - cVar22;
    auVar34[5] = bVar80 - cVar22;
    auVar34[6] = bVar81 - cVar22;
    auVar34[7] = bVar83 - cVar22;
    auVar34[8] = bVar84 - cVar22;
    auVar34[9] = bVar86 - cVar22;
    auVar34[10] = bVar87 - cVar22;
    auVar34[0xb] = bVar89 - cVar22;
    auVar34[0xc] = bVar90 - cVar22;
    auVar34[0xd] = bVar92 - cVar22;
    auVar34[0xe] = bVar93 - cVar22;
    auVar34[0xf] = auVar226[0xf] - cVar22;
    auVar35 = a64_TBL(ZEXT816(0),_DAT_7102ec0470,auVar34);
    uVar24 = (auVar35._0_8_ | auVar35._0_8_ >> 5) & 0xff00ff00ff00ff;
    uVar24 = uVar24 | uVar24 >> 10;
    uVar31 = (auVar35._8_8_ | auVar35._8_8_ >> 5) & 0xff00ff00ff00ff;
    uVar31 = uVar31 | uVar31 >> 10;
    return (ulong)((uVar96 + 7 | uVar96 << 8) ^ param_4) |
           (uVar24 >> 0x14 & 0x3fff000 | uVar24 & 0x3fff) << 0x10 |
           (ulong)((uint)(uVar31 >> 0x14) & 0xfff000 | (uint)uVar31 & 0x3fff) << 0x28;
  }
  auVar99[0] = -(bVar57 == 0);
  auVar99[1] = -(bVar74 == 0);
  auVar99[2] = -(bVar75 == 0);
  auVar99[3] = -(bVar77 == 0);
  auVar99[4] = -(bVar78 == 0);
  auVar99[5] = -(bVar80 == 0);
  auVar99[6] = -(bVar81 == 0);
  auVar99[7] = -(bVar83 == 0);
  auVar99[8] = -(bVar84 == 0);
  auVar99[9] = -(bVar86 == 0);
  auVar99[10] = -(bVar87 == 0);
  auVar99[0xb] = -(bVar89 == 0);
  auVar99[0xc] = -(bVar90 == 0);
  auVar99[0xd] = -(bVar92 == 0);
  auVar99[0xe] = -(bVar93 == 0);
  auVar99[0xf] = -(auVar226[0xf] == 0);
  auVar103[0] = bVar57 | auVar99[0];
  auVar103[1] = bVar74 | auVar99[1];
  auVar103[2] = bVar75 | auVar99[2];
  auVar103[3] = bVar77 | auVar99[3];
  auVar103[4] = bVar78 | auVar99[4];
  auVar103[5] = bVar80 | auVar99[5];
  auVar103[6] = bVar81 | auVar99[6];
  auVar103[7] = bVar83 | auVar99[7];
  auVar103[8] = bVar84 | auVar99[8];
  auVar103[9] = bVar86 | auVar99[9];
  auVar103[10] = bVar87 | auVar99[10];
  auVar103[0xb] = bVar89 | auVar99[0xb];
  auVar103[0xc] = bVar90 | auVar99[0xc];
  auVar103[0xd] = bVar92 | auVar99[0xd];
  auVar103[0xe] = bVar93 | auVar99[0xe];
  auVar103[0xf] = auVar226[0xf] | auVar99[0xf];
  auVar104._1_15_ = auVar103._1_15_;
  auVar104[0] = NEON_uminv(auVar103,1);
  uVar96 = auVar104._0_4_ & 0xff;
  auVar59._1_15_ = auVar210._1_15_;
  auVar71._13_3_ = (undefined3)(uVar24 >> 0x28);
  auVar69._11_5_ = (undefined5)(uVar24 >> 0x18);
  auVar67._9_7_ = (undefined7)(uVar24 >> 8);
  auVar65._7_9_ = auVar210._7_9_;
  auVar63._5_11_ = auVar210._5_11_;
  auVar61._3_13_ = auVar210._3_13_;
  if (5 < (int)(iVar95 - uVar96)) {
    sVar27 = (short)iVar6;
    sVar32 = sVar27 + auVar98._0_2_ * 0xc;
    auVar213[0] = bVar57;
    auVar37._0_2_ = auVar213._0_2_;
    auVar37[2] = bVar74;
    auVar39._0_4_ = auVar37._0_4_;
    auVar39[4] = bVar75;
    auVar41._0_6_ = auVar39._0_6_;
    auVar41[6] = bVar77;
    auVar43._0_8_ = auVar41._0_8_;
    auVar43[8] = bVar78;
    auVar222._0_10_ = auVar43._0_10_;
    auVar222[10] = bVar80;
    auVar46._0_12_ = auVar222._0_12_;
    auVar46[0xc] = bVar81;
    auVar48._0_14_ = auVar46._0_14_;
    auVar48[0xe] = bVar83;
    auVar48[0xf] = auVar35[0xf];
    auVar36._2_14_ = auVar48._2_14_;
    auVar36._0_2_ = auVar37._0_2_ & 0xff;
    auVar38._4_12_ = auVar48._4_12_;
    auVar38._0_3_ = auVar36._0_3_;
    auVar38[3] = 0;
    auVar40._6_10_ = auVar48._6_10_;
    auVar40._0_5_ = auVar38._0_5_;
    auVar40[5] = 0;
    auVar42._8_8_ = auVar48._8_8_;
    auVar42._0_7_ = auVar40._0_7_;
    auVar42[7] = 0;
    auVar44._10_6_ = auVar48._10_6_;
    auVar44._0_9_ = auVar42._0_9_;
    auVar44[9] = 0;
    auVar45._12_4_ = auVar48._12_4_;
    auVar45._0_11_ = auVar44._0_11_;
    auVar45[0xb] = 0;
    auVar47._14_2_ = auVar48._14_2_;
    auVar47._0_13_ = auVar45._0_13_;
    auVar47[0xd] = 0;
    auVar49._0_15_ = auVar47._0_15_;
    auVar49[0xf] = 0;
    auVar59[0] = bVar84;
    auVar61._0_2_ = auVar59._0_2_;
    auVar61[2] = bVar86;
    auVar63._0_4_ = auVar61._0_4_;
    auVar63[4] = bVar87;
    auVar65._0_6_ = auVar63._0_6_;
    auVar65[6] = bVar89;
    auVar67._0_8_ = auVar65._0_8_;
    auVar67[8] = bVar90;
    auVar69._0_10_ = auVar67._0_10_;
    auVar69[10] = bVar92;
    auVar71._0_12_ = auVar69._0_12_;
    auVar71[0xc] = bVar93;
    auVar226._0_14_ = auVar71._0_14_;
    auVar226[0xe] = auVar226[0xf];
    auVar60._2_14_ = auVar226._2_14_;
    auVar60._0_2_ = auVar61._0_2_ & 0xff;
    auVar62._4_12_ = auVar226._4_12_;
    auVar62._0_3_ = auVar60._0_3_;
    auVar62[3] = 0;
    auVar64._6_10_ = auVar226._6_10_;
    auVar64._0_5_ = auVar62._0_5_;
    auVar64[5] = 0;
    auVar66._8_8_ = auVar226._8_8_;
    auVar66._0_7_ = auVar64._0_7_;
    auVar66[7] = 0;
    auVar68._10_6_ = auVar226._10_6_;
    auVar68._0_9_ = auVar66._0_9_;
    auVar68[9] = 0;
    auVar70._12_4_ = auVar226._12_4_;
    auVar70._0_11_ = auVar68._0_11_;
    auVar70[0xb] = 0;
    auVar72._14_2_ = auVar226._14_2_;
    auVar72._0_13_ = auVar70._0_13_;
    auVar72[0xd] = 0;
    auVar73._0_15_ = auVar72._0_15_;
    auVar73[0xf] = 0;
    sVar28 = (short)(iVar95 - uVar96);
    sVar25 = (short)(iVar95 << 3) - sVar28;
    sVar27 = auVar97._0_2_ * 0xc - sVar27;
    sVar28 = sVar28 + (short)(uVar96 << 3);
    uVar76 = (ushort)bVar86;
    uVar79 = (ushort)bVar87;
    uVar82 = (ushort)bVar89;
    uVar85 = (ushort)bVar90;
    uVar88 = (ushort)bVar92;
    uVar91 = (ushort)bVar93;
    uVar94 = auVar72._14_2_ & 0xff;
    uVar50 = (ushort)bVar74;
    uVar51 = (ushort)bVar75;
    uVar52 = (ushort)bVar77;
    uVar53 = (ushort)bVar78;
    uVar54 = (ushort)bVar80;
    uVar55 = (ushort)bVar81;
    uVar56 = auVar47._14_2_ & 0xff;
    sVar12 = -(ushort)((short)(auVar36._0_2_ * 0xc) <= sVar32);
    sVar13 = -(ushort)((short)(uVar50 * 0xc) <= sVar32);
    sVar14 = -(ushort)((short)(uVar51 * 0xc) <= sVar32);
    sVar15 = -(ushort)((short)(uVar52 * 0xc) <= sVar32);
    sVar29 = -(ushort)((short)(uVar53 * 0xc) <= sVar32);
    sVar33 = -(ushort)((short)(uVar54 * 0xc) <= sVar32);
    sVar16 = -(ushort)((short)(uVar55 * 0xc) <= sVar32);
    sVar18 = -(ushort)((short)(uVar56 * 0xc) <= sVar32);
    sVar102 = -(ushort)((short)(auVar60._0_2_ * 0xc) <= sVar32);
    sVar108 = -(ushort)((short)(uVar76 * 0xc) <= sVar32);
    sVar109 = -(ushort)((short)(uVar79 * 0xc) <= sVar32);
    sVar110 = -(ushort)((short)(uVar82 * 0xc) <= sVar32);
    sVar111 = -(ushort)((short)(uVar85 * 0xc) <= sVar32);
    sVar112 = -(ushort)((short)(uVar88 * 0xc) <= sVar32);
    sVar113 = -(ushort)((short)(uVar91 * 0xc) <= sVar32);
    sVar32 = -(ushort)((short)(uVar94 * 0xc) <= sVar32);
    sVar158 = -(ushort)(sVar27 <= (short)(auVar36._0_2_ * 0xc));
    sVar160 = -(ushort)(sVar27 <= (short)(uVar50 * 0xc));
    sVar161 = -(ushort)(sVar27 <= (short)(uVar51 * 0xc));
    sVar162 = -(ushort)(sVar27 <= (short)(uVar52 * 0xc));
    sVar163 = -(ushort)(sVar27 <= (short)(uVar53 * 0xc));
    sVar164 = -(ushort)(sVar27 <= (short)(uVar54 * 0xc));
    sVar165 = -(ushort)(sVar27 <= (short)(uVar55 * 0xc));
    sVar166 = -(ushort)(sVar27 <= (short)(uVar56 * 0xc));
    sVar114 = -(ushort)(sVar27 <= (short)(auVar60._0_2_ * 0xc));
    sVar118 = -(ushort)(sVar27 <= (short)(uVar76 * 0xc));
    sVar119 = -(ushort)(sVar27 <= (short)(uVar79 * 0xc));
    sVar120 = -(ushort)(sVar27 <= (short)(uVar82 * 0xc));
    sVar121 = -(ushort)(sVar27 <= (short)(uVar85 * 0xc));
    sVar122 = -(ushort)(sVar27 <= (short)(uVar88 * 0xc));
    sVar123 = -(ushort)(sVar27 <= (short)(uVar91 * 0xc));
    sVar27 = -(ushort)(sVar27 <= (short)(uVar94 * 0xc));
    sVar168 = -(ushort)((short)(auVar36._0_2_ << 3) <= sVar28);
    sVar178 = -(ushort)((short)(uVar50 << 3) <= sVar28);
    sVar180 = -(ushort)((short)(uVar51 << 3) <= sVar28);
    sVar182 = -(ushort)((short)(uVar52 << 3) <= sVar28);
    sVar184 = -(ushort)((short)(uVar53 << 3) <= sVar28);
    sVar185 = -(ushort)((short)(uVar54 << 3) <= sVar28);
    sVar186 = -(ushort)((short)(uVar55 << 3) <= sVar28);
    sVar187 = -(ushort)((short)(uVar56 << 3) <= sVar28);
    sVar125 = -(ushort)((short)(auVar60._0_2_ << 3) <= sVar28);
    sVar135 = -(ushort)((short)(uVar76 << 3) <= sVar28);
    sVar137 = -(ushort)((short)(uVar79 << 3) <= sVar28);
    sVar139 = -(ushort)((short)(uVar82 << 3) <= sVar28);
    sVar141 = -(ushort)((short)(uVar85 << 3) <= sVar28);
    sVar142 = -(ushort)((short)(uVar88 << 3) <= sVar28);
    sVar143 = -(ushort)((short)(uVar91 << 3) <= sVar28);
    sVar144 = -(ushort)((short)(uVar94 << 3) <= sVar28);
    bVar124 = (byte)sVar125 & ~(byte)-(ushort)(auVar60._0_2_ == 0);
    sVar28 = CONCAT11((byte)((ushort)sVar125 >> 8) &
                      ~(byte)((ushort)-(ushort)(auVar60._0_2_ == 0) >> 8),bVar124);
    bVar134 = (byte)sVar135 & ~(byte)-(ushort)(uVar76 == 0);
    uVar126 = CONCAT13((byte)((ushort)sVar135 >> 8) & ~(byte)((ushort)-(ushort)(uVar76 == 0) >> 8),
                       CONCAT12(bVar134,sVar28));
    bVar136 = (byte)sVar137 & ~(byte)-(ushort)(uVar79 == 0);
    uVar127 = CONCAT15((byte)((ushort)sVar137 >> 8) & ~(byte)((ushort)-(ushort)(uVar79 == 0) >> 8),
                       CONCAT14(bVar136,uVar126));
    bVar138 = (byte)sVar139 & ~(byte)-(ushort)(uVar82 == 0);
    uVar128 = CONCAT17((byte)((ushort)sVar139 >> 8) & ~(byte)((ushort)-(ushort)(uVar82 == 0) >> 8),
                       CONCAT16(bVar138,uVar127));
    bVar140 = (byte)sVar141 & ~(byte)-(ushort)(uVar85 == 0);
    auVar129._0_10_ =
         CONCAT19((byte)((ushort)sVar141 >> 8) & ~(byte)((ushort)-(ushort)(uVar85 == 0) >> 8),
                  CONCAT18(bVar140,uVar128));
    auVar129[10] = (byte)sVar142 & ~(byte)-(ushort)(uVar88 == 0);
    auVar129[0xb] = (byte)((ushort)sVar142 >> 8) & ~(byte)((ushort)-(ushort)(uVar88 == 0) >> 8);
    auVar130[0xc] = (byte)sVar143 & ~(byte)-(ushort)(uVar91 == 0);
    auVar130._0_12_ = auVar129;
    auVar130[0xd] = (byte)((ushort)sVar143 >> 8) & ~(byte)((ushort)-(ushort)(uVar91 == 0) >> 8);
    auVar131[0xe] = (byte)sVar144 & ~(byte)-(ushort)(uVar94 == 0);
    auVar131._0_14_ = auVar130;
    auVar131[0xf] = (byte)((ushort)sVar144 >> 8) & ~(byte)((ushort)-(ushort)(uVar94 == 0) >> 8);
    bVar167 = (byte)sVar168 & ~(byte)-(ushort)(auVar36._0_2_ == 0);
    sVar168 = CONCAT11((byte)((ushort)sVar168 >> 8) &
                       ~(byte)((ushort)-(ushort)(auVar36._0_2_ == 0) >> 8),bVar167);
    bVar177 = (byte)sVar178 & ~(byte)-(ushort)(uVar50 == 0);
    uVar169 = CONCAT13((byte)((ushort)sVar178 >> 8) & ~(byte)((ushort)-(ushort)(uVar50 == 0) >> 8),
                       CONCAT12(bVar177,sVar168));
    bVar179 = (byte)sVar180 & ~(byte)-(ushort)(uVar51 == 0);
    uVar170 = CONCAT15((byte)((ushort)sVar180 >> 8) & ~(byte)((ushort)-(ushort)(uVar51 == 0) >> 8),
                       CONCAT14(bVar179,uVar169));
    bVar181 = (byte)sVar182 & ~(byte)-(ushort)(uVar52 == 0);
    uVar171 = CONCAT17((byte)((ushort)sVar182 >> 8) & ~(byte)((ushort)-(ushort)(uVar52 == 0) >> 8),
                       CONCAT16(bVar181,uVar170));
    bVar183 = (byte)sVar184 & ~(byte)-(ushort)(uVar53 == 0);
    auVar172._0_10_ =
         CONCAT19((byte)((ushort)sVar184 >> 8) & ~(byte)((ushort)-(ushort)(uVar53 == 0) >> 8),
                  CONCAT18(bVar183,uVar171));
    auVar172[10] = (byte)sVar185 & ~(byte)-(ushort)(uVar54 == 0);
    auVar172[0xb] = (byte)((ushort)sVar185 >> 8) & ~(byte)((ushort)-(ushort)(uVar54 == 0) >> 8);
    auVar173[0xc] = (byte)sVar186 & ~(byte)-(ushort)(uVar55 == 0);
    auVar173._0_12_ = auVar172;
    auVar173[0xd] = (byte)((ushort)sVar186 >> 8) & ~(byte)((ushort)-(ushort)(uVar55 == 0) >> 8);
    auVar174[0xe] = (byte)sVar187 & ~(byte)-(ushort)(uVar56 == 0);
    auVar174._0_14_ = auVar173;
    auVar174[0xf] = (byte)((ushort)sVar187 >> 8) & ~(byte)((ushort)-(ushort)(uVar56 == 0) >> 8);
    sVar178 = -(ushort)(sVar25 <= (short)(auVar36._0_2_ << 3));
    sVar180 = -(ushort)(sVar25 <= (short)(uVar50 << 3));
    sVar182 = -(ushort)(sVar25 <= (short)(uVar51 << 3));
    sVar184 = -(ushort)(sVar25 <= (short)(uVar52 << 3));
    sVar185 = -(ushort)(sVar25 <= (short)(uVar53 << 3));
    sVar186 = -(ushort)(sVar25 <= (short)(uVar54 << 3));
    sVar187 = -(ushort)(sVar25 <= (short)(uVar55 << 3));
    sVar201 = -(ushort)(sVar25 <= (short)(uVar56 << 3));
    sVar125 = -(ushort)(sVar25 <= (short)(auVar60._0_2_ << 3));
    sVar135 = -(ushort)(sVar25 <= (short)(uVar76 << 3));
    sVar137 = -(ushort)(sVar25 <= (short)(uVar79 << 3));
    sVar139 = -(ushort)(sVar25 <= (short)(uVar82 << 3));
    sVar141 = -(ushort)(sVar25 <= (short)(uVar85 << 3));
    sVar142 = -(ushort)(sVar25 <= (short)(uVar88 << 3));
    sVar143 = -(ushort)(sVar25 <= (short)(uVar91 << 3));
    sVar144 = -(ushort)(sVar25 <= (short)(uVar94 << 3));
    bVar145 = (byte)sVar125 & ~(byte)-(ushort)(auVar60._0_2_ == 0xff);
    sVar25 = CONCAT11((byte)((ushort)sVar125 >> 8) &
                      ~(byte)((ushort)-(ushort)(auVar60._0_2_ == 0xff) >> 8),bVar145);
    bVar154 = (byte)sVar135 & ~(byte)-(ushort)(uVar76 == 0xff);
    uVar146 = CONCAT13((byte)((ushort)sVar135 >> 8) &
                       ~(byte)((ushort)-(ushort)(uVar76 == 0xff) >> 8),CONCAT12(bVar154,sVar25));
    bVar155 = (byte)sVar137 & ~(byte)-(ushort)(uVar79 == 0xff);
    uVar147 = CONCAT15((byte)((ushort)sVar137 >> 8) &
                       ~(byte)((ushort)-(ushort)(uVar79 == 0xff) >> 8),CONCAT14(bVar155,uVar146));
    bVar156 = (byte)sVar139 & ~(byte)-(ushort)(uVar82 == 0xff);
    uVar148 = CONCAT17((byte)((ushort)sVar139 >> 8) &
                       ~(byte)((ushort)-(ushort)(uVar82 == 0xff) >> 8),CONCAT16(bVar156,uVar147));
    bVar157 = (byte)sVar141 & ~(byte)-(ushort)(uVar85 == 0xff);
    auVar149._0_10_ =
         CONCAT19((byte)((ushort)sVar141 >> 8) & ~(byte)((ushort)-(ushort)(uVar85 == 0xff) >> 8),
                  CONCAT18(bVar157,uVar148));
    auVar149[10] = (byte)sVar142 & ~(byte)-(ushort)(uVar88 == 0xff);
    auVar149[0xb] = (byte)((ushort)sVar142 >> 8) & ~(byte)((ushort)-(ushort)(uVar88 == 0xff) >> 8);
    auVar150[0xc] = (byte)sVar143 & ~(byte)-(ushort)(uVar91 == 0xff);
    auVar150._0_12_ = auVar149;
    auVar150[0xd] = (byte)((ushort)sVar143 >> 8) & ~(byte)((ushort)-(ushort)(uVar91 == 0xff) >> 8);
    auVar151[0xe] = (byte)sVar144 & ~(byte)-(ushort)(uVar94 == 0xff);
    auVar151._0_14_ = auVar150;
    auVar151[0xf] = (byte)((ushort)sVar144 >> 8) & ~(byte)((ushort)-(ushort)(uVar94 == 0xff) >> 8);
    bVar188 = (byte)sVar178 & ~(byte)-(ushort)(auVar36._0_2_ == 0xff);
    sVar125 = CONCAT11((byte)((ushort)sVar178 >> 8) &
                       ~(byte)((ushort)-(ushort)(auVar36._0_2_ == 0xff) >> 8),bVar188);
    bVar197 = (byte)sVar180 & ~(byte)-(ushort)(uVar50 == 0xff);
    uVar189 = CONCAT13((byte)((ushort)sVar180 >> 8) &
                       ~(byte)((ushort)-(ushort)(uVar50 == 0xff) >> 8),CONCAT12(bVar197,sVar125));
    bVar198 = (byte)sVar182 & ~(byte)-(ushort)(uVar51 == 0xff);
    uVar190 = CONCAT15((byte)((ushort)sVar182 >> 8) &
                       ~(byte)((ushort)-(ushort)(uVar51 == 0xff) >> 8),CONCAT14(bVar198,uVar189));
    bVar199 = (byte)sVar184 & ~(byte)-(ushort)(uVar52 == 0xff);
    uVar191 = CONCAT17((byte)((ushort)sVar184 >> 8) &
                       ~(byte)((ushort)-(ushort)(uVar52 == 0xff) >> 8),CONCAT16(bVar199,uVar190));
    bVar200 = (byte)sVar185 & ~(byte)-(ushort)(uVar53 == 0xff);
    auVar192._0_10_ =
         CONCAT19((byte)((ushort)sVar185 >> 8) & ~(byte)((ushort)-(ushort)(uVar53 == 0xff) >> 8),
                  CONCAT18(bVar200,uVar191));
    auVar192[10] = (byte)sVar186 & ~(byte)-(ushort)(uVar54 == 0xff);
    auVar192[0xb] = (byte)((ushort)sVar186 >> 8) & ~(byte)((ushort)-(ushort)(uVar54 == 0xff) >> 8);
    auVar193[0xc] = (byte)sVar187 & ~(byte)-(ushort)(uVar55 == 0xff);
    auVar193._0_12_ = auVar192;
    auVar193[0xd] = (byte)((ushort)sVar187 >> 8) & ~(byte)((ushort)-(ushort)(uVar55 == 0xff) >> 8);
    auVar194[0xe] = (byte)sVar201 & ~(byte)-(ushort)(uVar56 == 0xff);
    auVar194._0_14_ = auVar193;
    auVar194[0xf] = (byte)((ushort)sVar201 >> 8) & ~(byte)((ushort)-(ushort)(uVar56 == 0xff) >> 8);
    uVar96 = *(int *)(&DAT_71030bb480 +
                     (ulong)(uint)-(int)(short)(sVar102 + sVar12 + sVar108 + sVar13 +
                                                sVar109 + sVar14 + sVar110 + sVar15 +
                                               sVar111 + sVar29 + sVar112 + sVar33 +
                                               sVar113 + sVar16 + sVar32 + sVar18) * 4) *
             (int)(short)((ushort)((byte)sVar102 & bVar84) + (ushort)((byte)sVar12 & bVar57) +
                          (ushort)((byte)sVar108 & bVar86) + (ushort)((byte)sVar13 & bVar74) +
                          (ushort)((byte)sVar109 & bVar87) + (ushort)((byte)sVar14 & bVar75) +
                          (ushort)((byte)sVar110 & bVar89) + (ushort)((byte)sVar15 & bVar77) +
                         (ushort)((byte)sVar111 & bVar90) + (ushort)((byte)sVar29 & bVar78) +
                         (ushort)((byte)sVar112 & bVar92) + (ushort)((byte)sVar33 & bVar80) +
                         (ushort)((byte)sVar113 & bVar93) + (ushort)((byte)sVar16 & bVar81) +
                         (ushort)((byte)sVar32 & auVar226[0xf]) + (ushort)((byte)sVar18 & bVar83)) +
             0x80000;
    uVar2 = uVar96 >> 0x14;
    uVar23 = (ushort)(uVar96 >> 0x14);
    uVar96 = *(int *)(&DAT_71030bb480 +
                     (ulong)(uint)-(int)(short)(sVar114 + sVar158 + sVar118 + sVar160 +
                                                sVar119 + sVar161 + sVar120 + sVar162 +
                                               sVar121 + sVar163 + sVar122 + sVar164 +
                                               sVar123 + sVar165 + sVar27 + sVar166) * 4) *
             (int)(short)((ushort)((byte)sVar114 & bVar84) + (ushort)((byte)sVar158 & bVar57) +
                          (ushort)((byte)sVar118 & bVar86) + (ushort)((byte)sVar160 & bVar74) +
                          (ushort)((byte)sVar119 & bVar87) + (ushort)((byte)sVar161 & bVar75) +
                          (ushort)((byte)sVar120 & bVar89) + (ushort)((byte)sVar162 & bVar77) +
                         (ushort)((byte)sVar121 & bVar90) + (ushort)((byte)sVar163 & bVar78) +
                         (ushort)((byte)sVar122 & bVar92) + (ushort)((byte)sVar164 & bVar80) +
                         (ushort)((byte)sVar123 & bVar93) + (ushort)((byte)sVar165 & bVar81) +
                         (ushort)((byte)sVar27 & auVar226[0xf]) + (ushort)((byte)sVar166 & bVar83))
             + 0x80000U >> 0x14;
    uVar5 = *(int *)(&DAT_71030bb480 +
                    (ulong)(uint)-(int)(short)(sVar28 + sVar168 +
                                               (short)((uint)uVar126 >> 0x10) +
                                               (short)((uint)uVar169 >> 0x10) +
                                               (short)((uint6)uVar127 >> 0x20) +
                                               (short)((uint6)uVar170 >> 0x20) +
                                               (short)((ulong)uVar128 >> 0x30) +
                                               (short)((ulong)uVar171 >> 0x30) +
                                              (short)((unkuint10)auVar129._0_10_ >> 0x40) +
                                              (short)((unkuint10)auVar172._0_10_ >> 0x40) +
                                              auVar129._10_2_ + auVar172._10_2_ +
                                              auVar130._12_2_ + auVar173._12_2_ +
                                              auVar131._14_2_ + auVar174._14_2_) * 4) *
            (int)(short)((ushort)(bVar124 & bVar84) + (ushort)(bVar167 & bVar57) +
                         (ushort)(bVar134 & bVar86) + (ushort)(bVar177 & bVar74) +
                         (ushort)(bVar136 & bVar87) + (ushort)(bVar179 & bVar75) +
                         (ushort)(bVar138 & bVar89) + (ushort)(bVar181 & bVar77) +
                        (ushort)(bVar140 & bVar90) + (ushort)(bVar183 & bVar78) +
                        (ushort)(auVar129[10] & bVar92) + (ushort)(auVar172[10] & bVar80) +
                        (ushort)(auVar130[0xc] & bVar93) + (ushort)(auVar173[0xc] & bVar81) +
                        (ushort)(auVar131[0xe] & auVar226[0xf]) + (ushort)(auVar174[0xe] & bVar83))
            + 0x80000;
    uVar3 = uVar5 >> 0x14;
    uVar4 = *(int *)(&DAT_71030bb480 +
                    (ulong)(uint)-(int)(short)(sVar25 + sVar125 +
                                               (short)((uint)uVar146 >> 0x10) +
                                               (short)((uint)uVar189 >> 0x10) +
                                               (short)((uint6)uVar147 >> 0x20) +
                                               (short)((uint6)uVar190 >> 0x20) +
                                               (short)((ulong)uVar148 >> 0x30) +
                                               (short)((ulong)uVar191 >> 0x30) +
                                              (short)((unkuint10)auVar149._0_10_ >> 0x40) +
                                              (short)((unkuint10)auVar192._0_10_ >> 0x40) +
                                              auVar149._10_2_ + auVar192._10_2_ +
                                              auVar150._12_2_ + auVar193._12_2_ +
                                              auVar151._14_2_ + auVar194._14_2_) * 4) *
            (int)(short)((ushort)(bVar145 & bVar84) + (ushort)(bVar188 & bVar57) +
                         (ushort)(bVar154 & bVar86) + (ushort)(bVar197 & bVar74) +
                         (ushort)(bVar155 & bVar87) + (ushort)(bVar198 & bVar75) +
                         (ushort)(bVar156 & bVar89) + (ushort)(bVar199 & bVar77) +
                        (ushort)(bVar157 & bVar90) + (ushort)(bVar200 & bVar78) +
                        (ushort)(auVar149[10] & bVar92) + (ushort)(auVar192[10] & bVar80) +
                        (ushort)(auVar150[0xc] & bVar93) + (ushort)(auVar193[0xc] & bVar81) +
                        (ushort)(auVar151[0xe] & auVar226[0xf]) + (ushort)(auVar194[0xe] & bVar83))
            + 0x80000U >> 0x14;
    if (0xfe < uVar96) {
      uVar96 = 0xff;
    }
    if (0xfe < uVar4) {
      uVar4 = 0xff;
    }
    uVar26 = (ushort)(uVar5 >> 0x14);
    sVar29 = (short)uVar4;
    sVar12 = *(short *)(&DAT_71030bb280 + (ulong)(uVar4 - uVar3) * 2);
    sVar13 = *(short *)(&DAT_71030bb080 + (ulong)(uVar96 - uVar2) * 2);
    auVar208._0_8_ =
         CONCAT44((int)(short)(uVar50 - uVar26) * (int)sVar12,
                  (int)(short)(auVar36._0_2_ - uVar26) * (int)sVar12);
    auVar208._8_4_ = (int)(short)(uVar51 - uVar26) * (int)sVar12;
    auVar208._12_4_ = (int)(short)(uVar52 - uVar26) * (int)sVar12;
    auVar115._0_8_ =
         CONCAT44((int)(short)(uVar54 - uVar26) * (int)sVar12,
                  (int)(short)(uVar53 - uVar26) * (int)sVar12);
    auVar115._8_4_ = (int)(short)(uVar55 - uVar26) * (int)sVar12;
    auVar115._12_4_ = (int)(short)(uVar56 - uVar26) * (int)sVar12;
    auVar175._0_4_ = (int)(short)(auVar60._0_2_ - uVar26) * (int)sVar12;
    auVar175._4_4_ = (int)(short)(uVar76 - uVar26) * (int)sVar12;
    auVar175._8_4_ = (int)(short)(uVar79 - uVar26) * (int)sVar12;
    auVar175._12_4_ = (int)(short)(uVar82 - uVar26) * (int)sVar12;
    auVar132._0_4_ = (int)(short)(uVar85 - uVar26) * (int)sVar12;
    auVar132._4_4_ = (int)(short)(uVar88 - uVar26) * (int)sVar12;
    auVar132._8_4_ = (int)(short)(uVar91 - uVar26) * (int)sVar12;
    auVar132._12_4_ = (int)(short)(uVar94 - uVar26) * (int)sVar12;
    auVar209._8_8_ = auVar208._8_8_;
    auVar209._0_8_ = NEON_sqrshrun(auVar208._0_8_,auVar208,0xc,4);
    auVar224._0_8_ =
         CONCAT44((int)(short)(uVar50 - uVar23) * (int)sVar13,
                  (int)(short)(auVar36._0_2_ - uVar23) * (int)sVar13);
    auVar224._8_4_ = (int)(short)(uVar51 - uVar23) * (int)sVar13;
    auVar224._12_4_ = (int)(short)(uVar52 - uVar23) * (int)sVar13;
    auVar217._0_8_ = CONCAT26(sVar13,CONCAT24(sVar13,CONCAT22(sVar13,sVar13)));
    auVar217._8_2_ = sVar13;
    auVar217._10_2_ = sVar13;
    auVar217._12_2_ = sVar13;
    auVar217._14_2_ = sVar13;
    auVar152._0_4_ = (int)(short)(auVar60._0_2_ - uVar23) * (int)sVar13;
    auVar152._4_4_ = (int)(short)(uVar76 - uVar23) * (int)sVar13;
    auVar152._8_4_ = (int)(short)(uVar79 - uVar23) * (int)sVar13;
    auVar152._12_4_ = (int)(short)(uVar82 - uVar23) * (int)sVar13;
    auVar218._8_8_ = auVar217._8_8_;
    auVar202._0_4_ = (int)(short)(uVar85 - uVar23) * (int)sVar13;
    auVar202._4_4_ = (int)(short)(uVar88 - uVar23) * (int)sVar13;
    auVar202._8_4_ = (int)(short)(uVar91 - uVar23) * (int)sVar13;
    auVar202._12_4_ = (int)(short)(uVar94 - uVar23) * (int)sVar13;
    auVar159._0_4_ = (int)(short)(uVar53 - uVar23) * (int)sVar13;
    auVar159._4_4_ = (int)(short)(uVar54 - uVar23) * (int)sVar13;
    auVar159._8_4_ = (int)(short)(uVar55 - uVar23) * (int)sVar13;
    auVar159._12_4_ = (int)(short)(uVar56 - uVar23) * (int)sVar13;
    auVar218._0_8_ = NEON_sqrshrun(auVar217._0_8_,auVar224,0xc,4);
    auVar210 = NEON_sqrshrun2(auVar209,auVar115,0xc,4);
    auVar116._8_8_ = auVar115._8_8_;
    auVar116._0_8_ = NEON_sqrshrun(auVar115._0_8_,auVar175,0xc,4);
    auVar225._8_8_ = auVar224._8_8_;
    auVar225._0_8_ = NEON_sqrshrun(auVar224._0_8_,auVar152,0xc,4);
    auVar35 = NEON_sqrshrun2(auVar116,auVar132,0xc,4);
    auVar133._8_2_ = 7;
    auVar133._0_8_ = 0x7000700070007;
    auVar133._10_2_ = 7;
    auVar133._12_2_ = 7;
    auVar133._14_2_ = 7;
    auVar219 = NEON_sqrshrun2(auVar218,auVar159,0xc,4);
    auVar226 = NEON_sqrshrun2(auVar225,auVar202,0xc,4);
    auVar203._8_2_ = 5;
    auVar203._0_8_ = 0x5000500050005;
    auVar203._10_2_ = 5;
    auVar203._12_2_ = 5;
    auVar203._14_2_ = 5;
    auVar176 = NEON_smin(auVar35,auVar203,2);
    auVar35 = NEON_smin(auVar226,auVar133,2);
    auVar226 = NEON_smin(auVar210,auVar203,2);
    auVar210 = NEON_smin(auVar219,auVar133,2);
    sVar33 = (short)uVar96;
    iVar95 = ((int)auVar226._2_2_ * (int)sVar29 +
             (int)(short)(5 - auVar226._2_2_) * (int)(short)uVar26) * 0x333;
    iVar6 = ((int)auVar226._4_2_ * (int)sVar29 +
            (int)(short)(5 - auVar226._4_2_) * (int)(short)uVar26) * 0x333;
    iVar17 = ((int)auVar226._6_2_ * (int)sVar29 +
             (int)(short)(5 - auVar226._6_2_) * (int)(short)uVar26) * 0x333;
    auVar227._0_4_ =
         ((int)auVar176._8_2_ * (int)sVar29 + (int)(short)(5 - auVar176._8_2_) * (int)(short)uVar26)
         * 0x333;
    auVar227._4_4_ =
         ((int)auVar176._10_2_ * (int)sVar29 +
         (int)(short)(5 - auVar176._10_2_) * (int)(short)uVar26) * 0x333;
    auVar227._8_4_ =
         ((int)auVar176._12_2_ * (int)sVar29 +
         (int)(short)(5 - auVar176._12_2_) * (int)(short)uVar26) * 0x333;
    auVar227._12_4_ =
         ((int)auVar176._14_2_ * (int)sVar29 +
         (int)(short)(5 - auVar176._14_2_) * (int)(short)uVar26) * 0x333;
    auVar153[0] = auVar210[0];
    auVar153[1] = auVar210[2];
    auVar153[2] = auVar210[4];
    auVar153[3] = auVar210[6];
    auVar153[4] = auVar210[8];
    auVar153[5] = auVar210[10];
    auVar153[6] = auVar210[0xc];
    auVar153[7] = auVar210[0xe];
    auVar153[8] = auVar35[0];
    auVar153[9] = auVar35[2];
    auVar153[10] = auVar35[4];
    auVar153[0xb] = auVar35[6];
    auVar153[0xc] = auVar35[8];
    auVar153[0xd] = auVar35[10];
    auVar153[0xe] = auVar35[0xc];
    auVar153[0xf] = auVar35[0xe];
    auVar204._0_8_ =
         CONCAT44(((int)auVar176._2_2_ * (int)sVar29 +
                  (int)(short)(5 - auVar176._2_2_) * (int)(short)uVar26) * 0x333,
                  ((int)auVar176._0_2_ * (int)sVar29 +
                  (int)(short)(5 - auVar176._0_2_) * (int)(short)uVar26) * 0x333);
    auVar204._8_4_ =
         ((int)auVar176._4_2_ * (int)sVar29 + (int)(short)(5 - auVar176._4_2_) * (int)(short)uVar26)
         * 0x333;
    auVar204._12_4_ =
         ((int)auVar176._6_2_ * (int)sVar29 + (int)(short)(5 - auVar176._6_2_) * (int)(short)uVar26)
         * 0x333;
    sVar12 = 7 - auVar35._8_2_;
    sVar13 = 7 - auVar35._10_2_;
    sVar14 = 7 - auVar35._12_2_;
    sVar15 = 7 - auVar35._14_2_;
    iVar216 = (int)auVar35._0_2_ * (int)sVar33 +
              (int)(short)(7 - auVar35._0_2_) * (int)(short)uVar23;
    iVar223 = (int)auVar35._2_2_ * (int)sVar33 +
              (int)(short)(7 - auVar35._2_2_) * (int)(short)uVar23;
    auVar220._0_8_ = CONCAT44(iVar223,iVar216);
    auVar220._8_4_ =
         (int)auVar35._4_2_ * (int)sVar33 + (int)(short)(7 - auVar35._4_2_) * (int)(short)uVar23;
    auVar220._12_4_ =
         (int)auVar35._6_2_ * (int)sVar33 + (int)(short)(7 - auVar35._6_2_) * (int)(short)uVar23;
    uVar126 = CONCAT13((char)((ushort)sVar13 >> 8),CONCAT12((char)sVar13,sVar12));
    uVar127 = CONCAT15((char)((ushort)sVar14 >> 8),CONCAT14((char)sVar14,uVar126));
    iVar207 = (int)auVar35._8_2_ * (int)sVar33 + (int)sVar12 * (int)(short)uVar23;
    iVar215 = (int)auVar35._10_2_ * (int)sVar33 +
              (int)(short)((uint)uVar126 >> 0x10) * (int)(short)uVar23;
    auVar211._0_8_ = CONCAT44(iVar215,iVar207);
    auVar211._8_4_ =
         (int)auVar35._12_2_ * (int)sVar33 +
         (int)(short)((uint6)uVar127 >> 0x20) * (int)(short)uVar23;
    auVar211._12_4_ =
         (int)auVar35._14_2_ * (int)sVar33 +
         (int)(short)(CONCAT17((char)((ushort)sVar15 >> 8),CONCAT16((char)sVar15,uVar127)) >> 0x30)
         * (int)(short)uVar23;
    auVar205._8_8_ = auVar204._8_8_;
    auVar205._0_8_ = NEON_sqrshrun(auVar204._0_8_,auVar204,0xc,4);
    auVar35 = NEON_sqrshrun2(auVar205,auVar227,0xc,4);
    auVar219 = NEON_uabd(auVar73,auVar35,2);
    auVar195._0_8_ = CONCAT44(iVar223 * 0x249,iVar216 * 0x249);
    auVar195._8_4_ = auVar220._8_4_ * 0x249;
    auVar195._12_4_ = auVar220._12_4_ * 0x249;
    auVar221._8_8_ = auVar220._8_8_;
    auVar20._4_4_ =
         ((int)auVar210._2_2_ * (int)sVar33 + (int)(short)(7 - auVar210._2_2_) * (int)(short)uVar23)
         * 0x249;
    auVar20._0_4_ =
         ((int)auVar210._0_2_ * (int)sVar33 + (int)(short)(7 - auVar210._0_2_) * (int)(short)uVar23)
         * 0x249;
    auVar20._8_4_ =
         ((int)auVar210._4_2_ * (int)sVar33 + (int)(short)(7 - auVar210._4_2_) * (int)(short)uVar23)
         * 0x249;
    auVar20._12_4_ =
         ((int)auVar210._6_2_ * (int)sVar33 + (int)(short)(7 - auVar210._6_2_) * (int)(short)uVar23)
         * 0x249;
    auVar221._0_8_ = NEON_sqrshrun(auVar220._0_8_,auVar20,0xc,4);
    auVar106._0_4_ = iVar207 * 0x249;
    auVar106._4_4_ = iVar215 * 0x249;
    auVar106._8_4_ = auVar211._8_4_ * 0x249;
    auVar106._12_4_ = auVar211._12_4_ * 0x249;
    auVar212._8_8_ = auVar211._8_8_;
    auVar9[4] = (char)iVar95;
    auVar9._0_4_ = ((int)auVar226._0_2_ * (int)sVar29 +
                   (int)(short)(5 - auVar226._0_2_) * (int)(short)uVar26) * 0x333;
    auVar9[5] = (char)((uint)iVar95 >> 8);
    auVar9[6] = (char)((uint)iVar95 >> 0x10);
    auVar9[7] = (char)((uint)iVar95 >> 0x18);
    auVar9[8] = (char)iVar6;
    auVar9[9] = (char)((uint)iVar6 >> 8);
    auVar9[10] = (char)((uint)iVar6 >> 0x10);
    auVar9[0xb] = (char)((uint)iVar6 >> 0x18);
    auVar9[0xc] = (char)iVar17;
    auVar9[0xd] = (char)((uint)iVar17 >> 8);
    auVar9[0xe] = (char)((uint)iVar17 >> 0x10);
    auVar9[0xf] = (char)((uint)iVar17 >> 0x18);
    auVar212._0_8_ = NEON_sqrshrun(auVar211._0_8_,auVar9,0xc,4);
    auVar19._4_4_ =
         ((int)auVar226._10_2_ * (int)sVar29 +
         (int)(short)(5 - auVar226._10_2_) * (int)(short)uVar26) * 0x333;
    auVar19._0_4_ =
         ((int)auVar226._8_2_ * (int)sVar29 + (int)(short)(5 - auVar226._8_2_) * (int)(short)uVar26)
         * 0x333;
    auVar19._8_4_ =
         ((int)auVar226._12_2_ * (int)sVar29 +
         (int)(short)(5 - auVar226._12_2_) * (int)(short)uVar26) * 0x333;
    auVar19._12_4_ =
         ((int)auVar226._14_2_ * (int)sVar29 +
         (int)(short)(5 - auVar226._14_2_) * (int)(short)uVar26) * 0x333;
    auVar35 = NEON_sqrshrun2(auVar212,auVar19,0xc,4);
    auVar196._8_8_ = auVar195._8_8_;
    auVar196._0_8_ = NEON_sqrshrun(auVar195._0_8_,auVar195,0xc,4);
    auVar35 = NEON_uabd(auVar49,auVar35,2);
    auVar21._4_4_ =
         ((int)auVar210._10_2_ * (int)sVar33 +
         (int)(short)(7 - auVar210._10_2_) * (int)(short)uVar23) * 0x249;
    auVar21._0_4_ =
         ((int)auVar210._8_2_ * (int)sVar33 + (int)(short)(7 - auVar210._8_2_) * (int)(short)uVar23)
         * 0x249;
    auVar21._8_4_ =
         ((int)auVar210._12_2_ * (int)sVar33 +
         (int)(short)(7 - auVar210._12_2_) * (int)(short)uVar23) * 0x249;
    auVar21._12_4_ =
         ((int)auVar210._14_2_ * (int)sVar33 +
         (int)(short)(7 - auVar210._14_2_) * (int)(short)uVar23) * 0x249;
    auVar222 = NEON_sqrshrun2(auVar221,auVar21,0xc,4);
    auVar210 = NEON_sqrshrun2(auVar196,auVar106,0xc,4);
    auVar107._0_2_ = 0xff - auVar36._0_2_;
    auVar107._2_2_ = 0xff - uVar50;
    auVar107._4_2_ = 0xff - uVar51;
    auVar107._6_2_ = 0xff - uVar52;
    auVar107._8_2_ = 0xff - uVar53;
    auVar107._10_2_ = 0xff - uVar54;
    auVar107._12_2_ = 0xff - uVar55;
    auVar107._14_2_ = 0xff - uVar56;
    auVar101._0_2_ = 0xff - auVar60._0_2_;
    auVar101._2_2_ = 0xff - uVar76;
    auVar101._4_2_ = 0xff - uVar79;
    auVar101._6_2_ = 0xff - uVar82;
    auVar101._8_2_ = 0xff - uVar85;
    auVar101._10_2_ = 0xff - uVar88;
    auVar101._12_2_ = 0xff - uVar91;
    auVar101._14_2_ = 0xff - uVar94;
    auVar228._0_2_ = -(ushort)(auVar35._0_2_ < auVar36._0_2_);
    auVar228._2_2_ = -(ushort)(auVar35._2_2_ < uVar50);
    auVar228._4_2_ = -(ushort)(auVar35._4_2_ < uVar51);
    auVar228._6_2_ = -(ushort)(auVar35._6_2_ < uVar52);
    auVar228._8_2_ = -(ushort)(auVar35._8_2_ < uVar53);
    auVar228._10_2_ = -(ushort)(auVar35._10_2_ < uVar54);
    auVar228._12_2_ = -(ushort)(auVar35._12_2_ < uVar55);
    auVar228._14_2_ = -(ushort)(auVar35._14_2_ < uVar56);
    sVar12 = -(ushort)(auVar35._0_2_ < auVar107._0_2_);
    sVar13 = -(ushort)(auVar35._2_2_ < auVar107._2_2_);
    uVar229 = (undefined1)sVar13;
    uVar230 = (undefined1)((ushort)sVar13 >> 8);
    sVar13 = -(ushort)(auVar35._4_2_ < auVar107._4_2_);
    uVar231 = (undefined1)sVar13;
    uVar232 = (undefined1)((ushort)sVar13 >> 8);
    sVar13 = -(ushort)(auVar35._6_2_ < auVar107._6_2_);
    uVar233 = (undefined1)sVar13;
    uVar234 = (undefined1)((ushort)sVar13 >> 8);
    sVar13 = -(ushort)(auVar35._8_2_ < auVar107._8_2_);
    uVar235 = (undefined1)sVar13;
    uVar236 = (undefined1)((ushort)sVar13 >> 8);
    sVar13 = -(ushort)(auVar35._10_2_ < auVar107._10_2_);
    uVar237 = (undefined1)sVar13;
    uVar238 = (undefined1)((ushort)sVar13 >> 8);
    sVar13 = -(ushort)(auVar35._12_2_ < auVar107._12_2_);
    uVar239 = (undefined1)sVar13;
    uVar240 = (undefined1)((ushort)sVar13 >> 8);
    sVar13 = -(ushort)(auVar35._14_2_ < auVar107._14_2_);
    uVar241 = (undefined1)sVar13;
    uVar242 = (undefined1)((ushort)sVar13 >> 8);
    auVar213 = NEON_umin(auVar35,auVar49,2);
    auVar35 = NEON_uabd(auVar49,auVar222,2);
    sVar13 = -(ushort)(auVar219._0_2_ < auVar101._0_2_);
    sVar14 = -(ushort)(auVar219._2_2_ < auVar101._2_2_);
    uVar243 = (undefined1)sVar14;
    uVar244 = (undefined1)((ushort)sVar14 >> 8);
    sVar14 = -(ushort)(auVar219._4_2_ < auVar101._4_2_);
    uVar245 = (undefined1)sVar14;
    uVar246 = (undefined1)((ushort)sVar14 >> 8);
    sVar14 = -(ushort)(auVar219._6_2_ < auVar101._6_2_);
    uVar247 = (undefined1)sVar14;
    uVar248 = (undefined1)((ushort)sVar14 >> 8);
    sVar14 = -(ushort)(auVar219._8_2_ < auVar101._8_2_);
    uVar249 = (undefined1)sVar14;
    uVar250 = (undefined1)((ushort)sVar14 >> 8);
    sVar14 = -(ushort)(auVar219._10_2_ < auVar101._10_2_);
    uVar251 = (undefined1)sVar14;
    uVar252 = (undefined1)((ushort)sVar14 >> 8);
    sVar14 = -(ushort)(auVar219._12_2_ < auVar101._12_2_);
    uVar253 = (undefined1)sVar14;
    uVar254 = (undefined1)((ushort)sVar14 >> 8);
    sVar14 = -(ushort)(auVar219._14_2_ < auVar101._14_2_);
    uVar255 = (undefined1)sVar14;
    uVar256 = (undefined1)((ushort)sVar14 >> 8);
    auVar7[2] = uVar229;
    auVar7._0_2_ = sVar12;
    auVar7[3] = uVar230;
    auVar7[4] = uVar231;
    auVar7[5] = uVar232;
    auVar7[6] = uVar233;
    auVar7[7] = uVar234;
    auVar7[8] = uVar235;
    auVar7[9] = uVar236;
    auVar7[10] = uVar237;
    auVar7[0xb] = uVar238;
    auVar7[0xc] = uVar239;
    auVar7[0xd] = uVar240;
    auVar7[0xe] = uVar241;
    auVar7[0xf] = uVar242;
    auVar107 = auVar107 ^ (auVar107 ^ auVar213) & auVar7;
    auVar213 = NEON_umin(auVar219,auVar73,2);
    auVar206._0_2_ = -(ushort)(auVar219._0_2_ < auVar60._0_2_);
    auVar206._2_2_ = -(ushort)(auVar219._2_2_ < uVar76);
    auVar206._4_2_ = -(ushort)(auVar219._4_2_ < uVar79);
    auVar206._6_2_ = -(ushort)(auVar219._6_2_ < uVar82);
    auVar206._8_2_ = -(ushort)(auVar219._8_2_ < uVar85);
    auVar206._10_2_ = -(ushort)(auVar219._10_2_ < uVar88);
    auVar206._12_2_ = -(ushort)(auVar219._12_2_ < uVar91);
    auVar206._14_2_ = -(ushort)(auVar219._14_2_ < uVar94);
    auVar210 = NEON_uabd(auVar73,auVar210,2);
    auVar10[2] = uVar243;
    auVar10._0_2_ = sVar13;
    auVar10[3] = uVar244;
    auVar10[4] = uVar245;
    auVar10[5] = uVar246;
    auVar10[6] = uVar247;
    auVar10[7] = uVar248;
    auVar10[8] = uVar249;
    auVar10[9] = uVar250;
    auVar10[10] = uVar251;
    auVar10[0xb] = uVar252;
    auVar10[0xc] = uVar253;
    auVar10[0xd] = uVar254;
    auVar10[0xe] = uVar255;
    auVar10[0xf] = uVar256;
    auVar101 = auVar101 ^ (auVar101 ^ auVar213) & auVar10;
    auVar214._8_2_ = 6;
    auVar214._0_8_ = 0x6000600060006;
    auVar214._10_2_ = 6;
    auVar214._12_2_ = 6;
    auVar214._14_2_ = 6;
    auVar226 = auVar226 ^ (auVar226 ^ auVar214) & ~auVar228;
    auVar8[2] = uVar229;
    auVar8._0_2_ = sVar12;
    auVar8[3] = uVar230;
    auVar8[4] = uVar231;
    auVar8[5] = uVar232;
    auVar8[6] = uVar233;
    auVar8[7] = uVar234;
    auVar8[8] = uVar235;
    auVar8[9] = uVar236;
    auVar8[10] = uVar237;
    auVar8[0xb] = uVar238;
    auVar8[0xc] = uVar239;
    auVar8[0xd] = uVar240;
    auVar8[0xe] = uVar241;
    auVar8[0xf] = uVar242;
    auVar226 = auVar226 ^ (auVar226 ^ auVar133) & ~auVar8;
    auVar117[1] = auVar226[2];
    auVar117[0] = auVar226[0];
    auVar117[2] = auVar226[4];
    auVar117[3] = auVar226[6];
    auVar117[4] = auVar226[8];
    auVar117[5] = auVar226[10];
    auVar117[6] = auVar226[0xc];
    auVar117[7] = auVar226[0xe];
    auVar11[2] = uVar243;
    auVar11._0_2_ = sVar13;
    auVar11[3] = uVar244;
    auVar11[4] = uVar245;
    auVar11[5] = uVar246;
    auVar11[6] = uVar247;
    auVar11[7] = uVar248;
    auVar11[8] = uVar249;
    auVar11[9] = uVar250;
    auVar11[10] = uVar251;
    auVar11[0xb] = uVar252;
    auVar11[0xc] = uVar253;
    auVar11[0xd] = uVar254;
    auVar11[0xe] = uVar255;
    auVar11[0xf] = uVar256;
    auVar133 = auVar133 ^ (auVar133 ^ auVar176 ^ (auVar176 ^ auVar214) & ~auVar206) & auVar11;
    auVar117[8] = auVar133[0];
    auVar117[9] = auVar133[2];
    auVar117[10] = auVar133[4];
    auVar117[0xb] = auVar133[6];
    auVar117[0xc] = auVar133[8];
    auVar117[0xd] = auVar133[10];
    auVar117[0xe] = auVar133[0xc];
    auVar117[0xf] = auVar133[0xe];
    auVar176 = a64_TBL(ZEXT816(0),_DAT_7102ec0470,auVar153);
    auVar226 = a64_TBL(ZEXT816(0),_DAT_7102ebfb60,auVar117);
    uStack_18 = auVar226._8_8_;
    local_20 = auVar226._0_8_;
    uStack_8 = auVar176._8_8_;
    uStack_10 = auVar176._0_8_;
    puVar1 = &uStack_10;
    uVar31 = (ulong)(uVar96 | uVar2 << 8);
    if ((ushort)(auVar107._0_2_ * auVar107._0_2_ + auVar101._0_2_ * auVar101._0_2_ +
                 auVar107._2_2_ * auVar107._2_2_ + auVar101._2_2_ * auVar101._2_2_ +
                 auVar107._4_2_ * auVar107._4_2_ + auVar101._4_2_ * auVar101._4_2_ +
                 auVar107._6_2_ * auVar107._6_2_ + auVar101._6_2_ * auVar101._6_2_ +
                auVar107._8_2_ * auVar107._8_2_ + auVar101._8_2_ * auVar101._8_2_ +
                auVar107._10_2_ * auVar107._10_2_ + auVar101._10_2_ * auVar101._10_2_ +
                auVar107._12_2_ * auVar107._12_2_ + auVar101._12_2_ * auVar101._12_2_ +
                auVar107._14_2_ * auVar107._14_2_ + auVar101._14_2_ * auVar101._14_2_) <=
        (ushort)(auVar35._0_2_ * auVar35._0_2_ + auVar210._0_2_ * auVar210._0_2_ +
                 auVar35._2_2_ * auVar35._2_2_ + auVar210._2_2_ * auVar210._2_2_ +
                 auVar35._4_2_ * auVar35._4_2_ + auVar210._4_2_ * auVar210._4_2_ +
                 auVar35._6_2_ * auVar35._6_2_ + auVar210._6_2_ * auVar210._6_2_ +
                auVar35._8_2_ * auVar35._8_2_ + auVar210._8_2_ * auVar210._8_2_ +
                auVar35._10_2_ * auVar35._10_2_ + auVar210._10_2_ * auVar210._10_2_ +
                auVar35._12_2_ * auVar35._12_2_ + auVar210._12_2_ * auVar210._12_2_ +
                auVar35._14_2_ * auVar35._14_2_ + auVar210._14_2_ * auVar210._14_2_)) {
      puVar1 = &local_20;
      uVar31 = (ulong)uVar3 | (ulong)uVar4 << 8;
    }
    uVar30 = (*puVar1 | *puVar1 >> 5) & 0xff00ff00ff00ff;
    uVar30 = uVar30 | uVar30 >> 10;
    uVar24 = (puVar1[1] | puVar1[1] >> 5) & 0xff00ff00ff00ff;
    uVar24 = uVar24 | uVar24 >> 10;
    return uVar31 ^ param_4 | (uVar30 >> 0x14 & 0x3fff000 | uVar30 & 0x3fff) << 0x10 |
           (ulong)((uint)(uVar24 >> 0x14) & 0xfff000 | (uint)uVar24 & 0x3fff) << 0x28;
  }
  if (0xf9 < uVar96) {
    uVar96 = 0xfa;
  }
  cVar22 = (char)uVar96;
  auVar58[0] = bVar57 - cVar22;
  auVar58[1] = bVar74 - cVar22;
  auVar58[2] = bVar75 - cVar22;
  auVar58[3] = bVar77 - cVar22;
  auVar58[4] = bVar78 - cVar22;
  auVar58[5] = bVar80 - cVar22;
  auVar58[6] = bVar81 - cVar22;
  auVar58[7] = bVar83 - cVar22;
  auVar58[8] = bVar84 - cVar22;
  auVar58[9] = bVar86 - cVar22;
  auVar58[10] = bVar87 - cVar22;
  auVar58[0xb] = bVar89 - cVar22;
  auVar58[0xc] = bVar90 - cVar22;
  auVar58[0xd] = bVar92 - cVar22;
  auVar58[0xe] = bVar93 - cVar22;
  auVar58[0xf] = auVar226[0xf] - cVar22;
  auVar105[8] = 6;
  auVar105._0_8_ = 0x606060606060606;
  auVar105[9] = 6;
  auVar105[10] = 6;
  auVar105[0xb] = 6;
  auVar105[0xc] = 6;
  auVar105[0xd] = 6;
  auVar105[0xe] = 6;
  auVar105[0xf] = 6;
  auVar58 = auVar58 ^ (auVar58 ^ auVar105) & auVar99;
  auVar100[8] = 7;
  auVar100._0_8_ = 0x707070707070707;
  auVar100[9] = 7;
  auVar100[10] = 7;
  auVar100[0xb] = 7;
  auVar100[0xc] = 7;
  auVar100[0xd] = 7;
  auVar100[0xe] = 7;
  auVar100[0xf] = 7;
  auVar35 = a64_TBL(ZEXT816(0),_DAT_7102ebfb60,auVar58 ^ (auVar58 ^ auVar100) & auVar35);
  uVar24 = (auVar35._0_8_ | auVar35._0_8_ >> 5) & 0xff00ff00ff00ff;
  uVar24 = uVar24 | uVar24 >> 10;
  uVar31 = (auVar35._8_8_ | auVar35._8_8_ >> 5) & 0xff00ff00ff00ff;
  uVar31 = uVar31 | uVar31 >> 10;
  return (ulong)((uVar96 | uVar96 << 8) + 0x500 ^ param_4) |
         (uVar24 >> 0x14 & 0x3fff000 | uVar24 & 0x3fff) << 0x10 |
         (ulong)((uint)(uVar31 >> 0x14) & 0xfff000 | (uint)uVar31 & 0x3fff) << 0x28;
}



void FUN_710000e070(void)

{
  char *pcVar1;
  
  pcVar1 = DAT_7103a68e38;
  if (*DAT_7103a68e38 != '\0') {
    return;
  }
  FUN_710000e0f0(DAT_7103a68e28,5,DAT_7103a68e08,DAT_7103a68e18);
  FUN_710000e0f0(DAT_7103a68e30,6,DAT_7103a68e10,DAT_7103a68e20);
  *pcVar1 = '\x01';
  return;
}



void FUN_710000e0f0(uint *param_1,uint param_2,undefined *param_3,undefined *param_4)

{
  byte *pbVar1;
  byte *pbVar2;
  byte *pbVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  byte local_640 [768];
  byte local_340 [768];
  
  FUN_710000e2f0((long)local_340,0,param_2,param_3);
  FUN_710000e2f0((long)local_640,1,param_2,param_4);
  lVar6 = 0;
  do {
    pbVar2 = local_340 + lVar6;
    lVar4 = lVar6 + 2;
    lVar5 = lVar6 + 1;
    pbVar3 = (byte *)(((ulong)local_640 | 2) + lVar6);
    pbVar1 = local_640 + lVar6;
    lVar6 = lVar6 + 3;
    *param_1 = (uint)local_340[lVar4] | (uint)*pbVar2 << 4 | (uint)local_340[lVar5] << 10 |
               (uint)*pbVar1 << 0x14 | (uint)pbVar3[-1] << 0x1a | (uint)*pbVar3 << 0x10;
    param_1 = param_1 + 1;
  } while (lVar6 != 0x300);
  return;
}



void FUN_710000e2f0(long param_1,int param_2,uint param_3,undefined *param_4)

{
  uint uVar1;
  undefined1 *puVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  long lVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  long lVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint local_80;
  uint local_7c;
  uint uStack_78;
  
  uVar20 = 1 << (ulong)(param_3 & 0x1f);
  uVar6 = 8 - param_3;
  uVar7 = param_3 - uVar6;
  uVar5 = uVar20;
  if (uVar20 < 2) {
    uVar5 = 1;
  }
  if (param_2 == 0) {
    lVar15 = 0;
    do {
      uVar16 = 0xffffffff;
      iVar11 = 0;
      local_7c = 0;
      uStack_78 = 0;
      uVar20 = 0;
      uVar22 = 0xffffffff;
      do {
        uVar17 = 0;
        uVar13 = uVar22;
        uVar18 = uVar20;
        uVar21 = uVar16;
        do {
          iVar12 = (*(code *)param_4)(uVar20,uVar20 << (ulong)(uVar6 & 0x1f) |
                                             uVar20 >> (ulong)(uVar7 & 0x1f),uVar17,
                                      uVar17 << (ulong)(uVar6 & 0x1f) |
                                      uVar17 >> (ulong)(uVar7 & 0x1f));
          uVar22 = (int)lVar15 - iVar12;
          uVar14 = -uVar22;
          if (-1 < (int)uVar22) {
            uVar14 = uVar22;
          }
          uVar19 = iVar11 + uVar17;
          if (-1 < (int)uVar18) {
            uVar19 = uVar18;
          }
          uVar22 = uVar14;
          uVar16 = uVar19;
          uVar1 = uVar20;
          uVar3 = uVar17;
          if (((uVar13 <= uVar14) &&
              (uVar22 = uVar13, uVar16 = uVar21, uVar1 = local_7c, uVar3 = uStack_78,
              uVar19 < uVar21)) &&
             (uVar22 = uVar14, uVar16 = uVar19, uVar1 = uVar20, uVar3 = uVar17, uVar14 != uVar13)) {
            uVar22 = uVar13;
            uVar16 = uVar21;
            uVar1 = local_7c;
            uVar3 = uStack_78;
          }
          uStack_78 = uVar3;
          local_7c = uVar1;
          uVar17 = uVar17 + 1;
          uVar18 = uVar18 - 1;
          uVar13 = uVar22;
          uVar21 = uVar16;
        } while (uVar5 != uVar17);
        uVar20 = uVar20 + 1;
        iVar11 = iVar11 + -1;
      } while (uVar20 != uVar5);
      lVar8 = lVar15 * 3;
      lVar15 = lVar15 + 1;
      puVar2 = (undefined1 *)(param_1 + lVar8);
      *puVar2 = (char)local_7c;
      puVar2[2] = (char)uVar22 * (char)uVar22;
      puVar2[1] = (char)uStack_78;
    } while (lVar15 != 0x100);
  }
  else {
    lVar15 = 0;
    do {
      uVar18 = 0xffffffff;
      uVar22 = 0;
      uVar17 = 0xffffffff;
      local_80 = 0;
      local_7c = 0;
      uVar16 = -uVar20;
      do {
        uStack_78 = (uint)lVar15;
        if (uVar22 < uVar20) {
          uVar13 = 0;
          uVar21 = 0;
          uVar14 = uVar17;
          uVar19 = uVar18;
          do {
            uVar1 = uVar22 + uVar13;
            iVar11 = (*(code *)param_4)(uVar22,uVar22 << (ulong)(uVar6 & 0x1f) |
                                               uVar22 >> (ulong)(uVar7 & 0x1f),uVar1,
                                        uVar1 << (ulong)(uVar6 & 0x1f) |
                                        uVar1 >> (ulong)(uVar7 & 0x1f));
            uVar17 = uStack_78 - iVar11;
            uVar3 = -uVar17;
            if (-1 < (int)uVar17) {
              uVar3 = uVar17;
            }
            uVar4 = uVar13;
            if (-1 < (int)uVar21) {
              uVar4 = uVar21;
            }
            uVar17 = uVar3;
            uVar18 = uVar4;
            uVar9 = uVar22;
            uVar10 = uVar1;
            if (((uVar14 <= uVar3) &&
                (uVar17 = uVar14, uVar18 = uVar19, uVar9 = local_80, uVar10 = local_7c,
                uVar4 < uVar19)) &&
               (uVar17 = uVar3, uVar18 = uVar4, uVar9 = uVar22, uVar10 = uVar1, uVar3 != uVar14)) {
              uVar17 = uVar14;
              uVar18 = uVar19;
              uVar9 = local_80;
              uVar10 = local_7c;
            }
            local_7c = uVar10;
            local_80 = uVar9;
            uVar21 = uVar21 - 1;
            uVar13 = uVar13 + 1;
            uVar14 = uVar17;
            uVar19 = uVar18;
          } while (uVar16 != uVar21);
        }
        uVar22 = uVar22 + 1;
        uVar16 = uVar16 + 1;
      } while (uVar22 != uVar5);
      puVar2 = (undefined1 *)(param_1 + lVar15 * 3);
      *puVar2 = (char)local_80;
      lVar15 = lVar15 + 1;
      puVar2[2] = (char)uVar17 * (char)uVar17;
      puVar2[1] = (char)local_7c;
    } while (lVar15 != 0x100);
  }
  return;
}



void FUN_7100010524(auto_FUN_7100010524_param_1 *param_1,undefined4 param_2,undefined4 param_3,
                   dword param_4,undefined4 param_5,undefined4 param_6)

{
  dword dVar1;
  dword dVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  uint uVar11;
  byte bVar12;
  byte bVar13;
  bool bVar14;
  int iVar15;
  uint uVar16;
  ulong uVar17;
  dword dVar18;
  dword dVar19;
  int iVar20;
  uint uVar21;
  byte bVar22;
  int iVar23;
  uint uVar24;
  
  *(undefined4 *)param_1 = param_2;
  *(undefined4 *)&param_1->field_0x4 = param_3;
  param_1->field_0x8_w = param_4;
  *(undefined4 *)&param_1->field_0xc = param_5;
  *(undefined4 *)&param_1->field_0x10 = param_6;
  *(undefined8 *)&param_1->field_0x14 = 0;
  *(undefined8 *)&param_1->field_0x1c = 0;
  *(undefined8 *)&param_1->field_0x24 = 0;
  *(undefined8 *)&param_1->field_0x2c = 0;
  *(undefined8 *)&param_1->field_0x34 = 0;
  *(undefined8 *)&param_1[1].field_0x1 = 0;
  *(undefined8 *)((long)&param_1[1].field_0x8_w + 1) = 0;
  *(undefined8 *)&param_1[1].field_0x11 = 0;
  *(undefined8 *)((long)&param_1[1].field_0x18_w + 1) = 0;
  *(undefined8 *)&param_1[1].field_0x21 = 0;
  *(undefined8 *)((long)&param_1[1].field_0x28_w + 1) = 0;
  *(undefined8 *)&param_1[1].field_0x31 = 0;
  *(undefined8 *)((long)&param_1[1].field_0x37_w + 2) = 0;
  *(undefined8 *)&param_1[2].field_0x6 = 0;
  *(undefined8 *)&param_1[2].field_0xe = 0;
  *(undefined8 *)&param_1[2].field_0x16 = 0;
  *(undefined8 *)&param_1[2].field_0x1e = 0;
  *(undefined8 *)&param_1[2].field_0x26 = 0;
  *(undefined8 *)&param_1[2].field_0x2e = 0;
  *(undefined8 *)&param_1[2].field_0x36 = 0;
  *(undefined8 *)&param_1[3].field_0x3 = 0;
  *(undefined8 *)((long)&param_1[3].field_0x8_w + 3) = 0;
  *(undefined8 *)&param_1[3].field_0x13 = 0;
  *(undefined8 *)((long)&param_1[3].field_0x18_w + 3) = 0;
  *(undefined8 *)&param_1[3].field_0x23 = 0;
  *(undefined4 *)((long)&param_1[3].field_0x28_w + 3) = 0;
  *(undefined8 *)&param_1->field_0x14 = 0;
  dVar18 = 1;
  switch(*(undefined4 *)param_1) {
  case 0:
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
    goto switchD_71000105dc_caseD_0;
  case 7:
  case 8:
  case 9:
  case 10:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xe:
    dVar18 = 4;
switchD_71000105dc_caseD_0:
    *(dword *)&param_1->field_0x14 = dVar18;
    param_1->field_0x18_w = dVar18;
    dVar19 = dVar18;
    switch(*(undefined4 *)param_1) {
    case 0:
    case 2:
    case 3:
      iVar20 = 2;
      break;
    case 1:
      iVar20 = 1;
      break;
    case 4:
    case 5:
    case 6:
      iVar20 = 4;
      break;
    case 7:
    case 10:
      iVar20 = 8;
      break;
    case 8:
    case 9:
    case 0xb:
    case 0xc:
    case 0xd:
    case 0xe:
      goto switchD_710001060c_caseD_8;
    default:
      iVar20 = 0;
    }
    goto LAB_7100010614;
  case 0xf:
    *(undefined8 *)&param_1->field_0x14 = 0x400000005;
    dVar18 = 4;
    dVar19 = 5;
    break;
  case 0x10:
    *(undefined8 *)&param_1->field_0x14 = 0x500000005;
    dVar18 = 5;
    dVar19 = 5;
    break;
  case 0x11:
    *(undefined8 *)&param_1->field_0x14 = 0x500000006;
    dVar18 = 5;
    dVar19 = 6;
    break;
  case 0x12:
    *(undefined8 *)&param_1->field_0x14 = 0x600000006;
    dVar18 = 6;
    dVar19 = 6;
    break;
  case 0x13:
    *(undefined8 *)&param_1->field_0x14 = 0x500000008;
    dVar18 = 5;
    dVar19 = 8;
    break;
  case 0x14:
    *(undefined8 *)&param_1->field_0x14 = 0x600000008;
    dVar18 = 6;
    dVar19 = 8;
    break;
  case 0x15:
    *(undefined8 *)&param_1->field_0x14 = 0x800000008;
    dVar18 = 8;
    dVar19 = 8;
    break;
  case 0x16:
    *(undefined8 *)&param_1->field_0x14 = 0x50000000a;
    dVar18 = 5;
    dVar19 = 10;
    break;
  case 0x17:
    *(undefined8 *)&param_1->field_0x14 = 0x60000000a;
    dVar18 = 6;
    dVar19 = 10;
    break;
  case 0x18:
    *(undefined8 *)&param_1->field_0x14 = 0x80000000a;
    dVar18 = 8;
    dVar19 = 10;
    break;
  case 0x19:
    *(undefined8 *)&param_1->field_0x14 = 0xa0000000a;
    dVar18 = 10;
    dVar19 = 10;
    break;
  case 0x1a:
    *(undefined8 *)&param_1->field_0x14 = 0xa0000000c;
    dVar18 = 10;
    dVar19 = 0xc;
    break;
  case 0x1b:
    *(undefined8 *)&param_1->field_0x14 = 0xc0000000c;
    dVar18 = 0xc;
    dVar19 = 0xc;
    break;
  default:
    dVar18 = 0;
    iVar20 = 0;
    dVar19 = 0;
    goto LAB_7100010614;
  }
switchD_710001060c_caseD_8:
  iVar20 = 0x10;
LAB_7100010614:
  dVar2 = param_1->field_0x8_w;
  iVar3 = *(int *)&param_1->field_0xc;
  dVar1 = dVar2;
  if ((int)dVar2 < 2) {
    dVar1 = 1;
  }
  iVar9 = dVar19 - 1;
  iVar5 = 0;
  if (dVar19 != 0) {
    iVar5 = (int)(iVar9 + dVar1) / (int)dVar19;
  }
  iVar15 = iVar3;
  if (iVar3 < 2) {
    iVar15 = 1;
  }
  iVar10 = dVar18 - 1;
  *(int *)&param_1->field_0x1c = iVar20;
  iVar23 = iVar5 * iVar20 + 0x3f;
  iVar5 = iVar5 * iVar20 + 0x7e;
  if (-1 < iVar23) {
    iVar5 = iVar23;
  }
  *(int *)((long)&param_1[2].field_0x28_w + 2) = iVar5 >> 6;
  iVar5 = 0;
  if (dVar18 != 0) {
    iVar5 = (iVar10 + iVar15) / (int)dVar18;
  }
  iVar15 = iVar5;
  if (iVar5 < 0) {
    iVar15 = iVar5 + 1;
  }
  iVar5 = iVar5 + (iVar15 >> 1);
  if (iVar5 < 0x80) {
    if (iVar5 < 0x40) {
      if (iVar5 < 0x20) {
        bVar12 = 0;
        bVar13 = 0;
        bVar22 = 0;
        uVar21 = (uint)(0xf < iVar5);
        bVar14 = 0xf < iVar5;
      }
      else {
        bVar13 = 0;
        bVar22 = 0;
        uVar21 = 2;
        bVar14 = true;
        bVar12 = 1;
      }
    }
    else {
      bVar22 = 0;
      uVar21 = 3;
      bVar14 = true;
      bVar12 = 1;
      bVar13 = 1;
    }
  }
  else {
    uVar21 = 4;
    bVar14 = true;
    bVar12 = 1;
    bVar13 = 1;
    bVar22 = 1;
  }
  iVar5 = *(int *)&param_1->field_0x4;
  uVar4 = *(uint *)&param_1->field_0x10;
  *(uint *)&param_1->field_0x20 = uVar21;
  if (iVar5 == 0x200) {
    if ((int)uVar4 < 1) {
      *(int *)&param_1[1].field_0x25 = 1 << (ulong)uVar21;
      return;
    }
    iVar15 = 0;
    uVar16 = 0;
    do {
      iVar23 = iVar3 >> (uVar16 & 0x1f);
      if (iVar23 < 2) {
        iVar23 = 1;
      }
      iVar7 = 0;
      if (dVar18 != 0) {
        iVar7 = (iVar10 + iVar23) / (int)dVar18;
      }
      iVar23 = (int)dVar2 >> (uVar16 & 0x1f);
      uVar24 = uVar21;
      if (((((bool)(bVar14 & iVar7 < 8 << (ulong)uVar21)) &&
           (uVar24 = uVar21 - 1, !(bool)(bVar12 ^ 1 | 8 << (ulong)(uVar21 - 1 & 0x1f) <= iVar7))) &&
          (uVar24 = uVar21 - 2, !(bool)(bVar13 ^ 1 | 8 << (ulong)(uVar21 - 2 & 0x1f) <= iVar7))) &&
         (uVar24 = uVar21 - 4, !(bool)(bVar22 & iVar7 < 8 << (ulong)(uVar21 - 3 & 0x1f)))) {
        uVar24 = uVar21 - 3;
      }
      if (iVar23 < 2) {
        iVar23 = 1;
      }
      iVar6 = 0;
      if (dVar19 != 0) {
        iVar6 = (iVar23 + iVar9) / (int)dVar19;
      }
      uVar16 = uVar16 + 1;
      iVar15 = ((iVar6 * iVar20 + 0x3f >> 6) *
                ((1 << (ulong)(uVar24 & 0x1f)) + (iVar7 + 7 >> 3) + -1 >> (uVar24 & 0x1f)) <<
               (ulong)(uVar24 + 9 & 0x1f)) + iVar15;
    } while (uVar4 != uVar16);
    iVar23 = 0;
    uVar16 = 0;
    do {
      iVar7 = iVar3 >> (uVar16 & 0x1f);
      iVar6 = (int)dVar2 >> (uVar16 & 0x1f);
      uVar16 = uVar16 + 1;
      if (iVar7 < 2) {
        iVar7 = 1;
      }
      if (iVar6 < 2) {
        iVar6 = 1;
      }
      iVar8 = 0;
      if (dVar19 != 0) {
        iVar8 = (iVar6 + iVar9) / (int)dVar19;
      }
      iVar6 = 0;
      if (dVar18 != 0) {
        iVar6 = (iVar10 + iVar7) / (int)dVar18;
      }
      iVar23 = iVar23 + (iVar8 * iVar20 + 0x3fU >> 6) * (iVar6 + 7U >> 3) * 0x200;
    } while (uVar4 != uVar16);
    if (iVar23 != iVar15) {
      uVar21 = 0;
      *(undefined4 *)&param_1->field_0x20 = 0;
    }
  }
  *(int *)&param_1[1].field_0x25 = 1 << (ulong)uVar21;
  if ((int)uVar4 < 2) {
    return;
  }
  uVar17 = 1;
  do {
    iVar15 = (int)dVar2 >> ((uint)uVar17 & 0x1f);
    if (iVar15 < 2) {
      iVar15 = 1;
    }
    iVar23 = 0;
    if (dVar19 != 0) {
      iVar23 = (iVar15 + iVar9) / (int)dVar19;
    }
    iVar15 = iVar23 * iVar20 + 0x3f;
    iVar23 = iVar23 * iVar20 + 0x7e;
    if (-1 < iVar15) {
      iVar23 = iVar15;
    }
    *(int *)((long)&param_1[2].field_0x28_w + uVar17 * 4 + 2) = iVar23 >> 6;
    if (0 < (int)uVar21) {
      iVar15 = iVar3 >> ((uint)uVar17 & 0x1f);
      if (iVar15 < 2) {
        iVar15 = 1;
      }
      iVar23 = 0;
      if (dVar18 != 0) {
        iVar23 = (iVar15 + iVar10) / (int)dVar18;
      }
      iVar15 = 8 << (ulong)(uVar21 - 1 & 0x1f);
      while ((iVar23 <= iVar15 && (uVar21 = uVar21 - 1, uVar21 != 0))) {
        if (iVar15 < 0) {
          iVar15 = iVar15 + 1;
        }
        iVar15 = iVar15 >> 1;
      }
    }
    *(uint *)(&param_1->field_0x20 + uVar17 * 4) = uVar21;
    if (iVar5 == 0x200) {
      iVar15 = 0;
      uVar16 = 0;
      do {
        iVar23 = iVar3 >> (uVar16 & 0x1f);
        if (iVar23 < 2) {
          iVar23 = 1;
        }
        iVar7 = 0;
        if (dVar18 != 0) {
          iVar7 = (iVar10 + iVar23) / (int)dVar18;
        }
        iVar23 = (int)dVar2 >> (uVar16 & 0x1f);
        uVar24 = uVar21;
        do {
          uVar11 = uVar24;
          if ((int)uVar11 < 1) break;
          uVar24 = uVar11 - 1;
        } while (iVar7 < 8 << (ulong)(uVar11 & 0x1f));
        if (iVar23 < 2) {
          iVar23 = 1;
        }
        iVar6 = 0;
        if (dVar19 != 0) {
          iVar6 = (iVar23 + iVar9) / (int)dVar19;
        }
        uVar16 = uVar16 + 1;
        iVar15 = ((iVar6 * iVar20 + 0x3f >> 6) *
                  ((1 << (ulong)(uVar11 & 0x1f)) + (iVar7 + 7 >> 3) + -1 >> (uVar11 & 0x1f)) <<
                 (ulong)(uVar11 + 9 & 0x1f)) + iVar15;
      } while (uVar16 != uVar4);
      iVar23 = 0;
      uVar16 = 0;
      do {
        iVar7 = iVar3 >> (uVar16 & 0x1f);
        iVar6 = (int)dVar2 >> (uVar16 & 0x1f);
        uVar16 = uVar16 + 1;
        if (iVar7 < 2) {
          iVar7 = 1;
        }
        if (iVar6 < 2) {
          iVar6 = 1;
        }
        iVar8 = 0;
        if (dVar19 != 0) {
          iVar8 = (iVar6 + iVar9) / (int)dVar19;
        }
        iVar6 = 0;
        if (dVar18 != 0) {
          iVar6 = (iVar10 + iVar7) / (int)dVar18;
        }
        iVar23 = iVar23 + (iVar8 * iVar20 + 0x3fU >> 6) * (iVar6 + 7U >> 3) * 0x200;
      } while (uVar4 != uVar16);
      if (iVar23 != iVar15) {
        uVar21 = 0;
        *(uint *)(&param_1->field_0x20 + uVar17 * 4) = 0;
      }
    }
    *(int *)(&param_1[1].field_0x25 + uVar17 * 4) = 1 << (ulong)(uVar21 & 0x1f);
    if (uVar17 + 1 == (ulong)uVar4) {
      return;
    }
    uVar21 = *(uint *)&param_1->field_0x20;
    uVar17 = uVar17 + 1;
  } while( true );
}



uint FUN_7100010bb0(long param_1,int param_2,ulong param_3,long param_4)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 0;
  if (param_2 != 0x200) {
    if (param_2 != 0) goto LAB_7100010be4;
    uVar2 = *(uint *)(param_1 + 0x20);
  }
  uVar2 = FUN_7100010c00(param_1,uVar2,param_4);
LAB_7100010be4:
  uVar1 = uVar2 + 0xfff & 0xfffff000;
  if ((param_3 & 1) == 0) {
    uVar1 = uVar2;
  }
  return uVar1;
}



int FUN_7100010c00(long param_1,uint param_2,long param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  long lVar9;
  uint uVar10;
  
  if (*(int *)(param_1 + 0x10) < 1) {
    return 0;
  }
  if (param_3 == 0) {
    iVar1 = *(int *)(param_1 + 0x14);
    iVar2 = *(int *)(param_1 + 0x18);
    iVar8 = 0;
    uVar10 = 0;
    do {
      iVar3 = *(int *)(param_1 + 8) >> (uVar10 & 0x1f);
      iVar4 = *(int *)(param_1 + 0xc) >> (uVar10 & 0x1f);
      if (iVar3 < 2) {
        iVar3 = 1;
      }
      if (iVar4 < 2) {
        iVar4 = 1;
      }
      iVar5 = 0;
      uVar7 = param_2;
      if (iVar2 != 0) {
        iVar5 = (iVar4 + iVar2 + -1) / iVar2;
      }
      do {
        uVar6 = uVar7;
        if ((int)uVar6 < 1) break;
        uVar7 = uVar6 - 1;
      } while (iVar5 < 8 << (ulong)(uVar6 & 0x1f));
      iVar4 = 0;
      if (iVar1 != 0) {
        iVar4 = (iVar1 + -1 + iVar3) / iVar1;
      }
      uVar10 = uVar10 + 1;
      iVar8 = ((*(int *)(param_1 + 0x1c) * iVar4 + 0x3f >> 6) *
               ((1 << (ulong)(uVar6 & 0x1f)) + (iVar5 + 7 >> 3) + -1 >> (uVar6 & 0x1f)) <<
              (ulong)(uVar6 + 9 & 0x1f)) + iVar8;
    } while ((int)uVar10 < *(int *)(param_1 + 0x10));
  }
  else {
    lVar9 = 0;
    iVar8 = 0;
    do {
      iVar1 = *(int *)(param_1 + 8) >> ((uint)lVar9 & 0x1f);
      iVar2 = *(int *)(param_1 + 0xc) >> ((uint)lVar9 & 0x1f);
      if (iVar1 < 2) {
        iVar1 = 1;
      }
      if (iVar2 < 2) {
        iVar2 = 1;
      }
      iVar3 = *(int *)(param_1 + 0x14);
      iVar4 = *(int *)(param_1 + 0x18);
      iVar5 = 0;
      uVar10 = param_2;
      if (iVar4 != 0) {
        iVar5 = (iVar2 + iVar4 + -1) / iVar4;
      }
      do {
        uVar7 = uVar10;
        if ((int)uVar7 < 1) break;
        uVar10 = uVar7 - 1;
      } while (iVar5 < 8 << (ulong)(uVar7 & 0x1f));
      iVar2 = 0;
      if (iVar3 != 0) {
        iVar2 = (iVar3 + iVar1 + -1) / iVar3;
      }
      iVar1 = (*(int *)(param_1 + 0x1c) * iVar2 + 0x3f >> 6) *
              ((1 << (ulong)(uVar7 & 0x1f)) + (iVar5 + 7 >> 3) + -1 >> (uVar7 & 0x1f)) <<
              (ulong)(uVar7 + 9 & 0x1f);
      iVar8 = iVar1 + iVar8;
      *(long *)(param_3 + lVar9 * 8) = (long)iVar1;
      lVar9 = lVar9 + 1;
    } while (lVar9 < *(int *)(param_1 + 0x10));
  }
  return iVar8;
}



undefined8
FUN_7100010d8c(long param_1,uint param_2,undefined8 *param_3,undefined8 param_4,long param_5)

{
  long lVar1;
  undefined8 *puVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  undefined8 *puVar15;
  uint uVar16;
  int iVar17;
  int iVar18;
  
  iVar18 = *(int *)(param_1 + 8) >> (param_2 & 0x1f);
  iVar6 = *(int *)(param_1 + 0x14);
  iVar7 = *(int *)(param_1 + 0x18);
  if (iVar18 < 2) {
    iVar18 = 1;
  }
  iVar11 = 0;
  if (iVar6 != 0) {
    iVar11 = (iVar6 + iVar18 + -1) / iVar6;
  }
  iVar18 = *(int *)(param_1 + 0xc) >> (param_2 & 0x1f);
  if (iVar18 < 2) {
    iVar18 = 1;
  }
  uVar12 = 0;
  if (iVar7 != 0) {
    uVar12 = (iVar7 + iVar18 + -1) / iVar7;
  }
  if (*(int *)(param_1 + 0x1c) == 0x10) {
    if ((0 < (int)uVar12) && (0 < iVar11)) {
      lVar1 = param_1 + (long)(int)param_2 * 4;
      uVar16 = 0;
      piVar3 = (int *)(lVar1 + 0x60);
      do {
        iVar18 = *piVar3;
        iVar6 = iVar18 * 8;
        iVar7 = 0;
        if (iVar6 != 0) {
          iVar7 = (int)uVar16 / iVar6;
        }
        iVar8 = *(int *)(lVar1 + 0xa0);
        iVar17 = 0;
        iVar9 = iVar7 * iVar18;
        puVar15 = param_3;
        while( true ) {
          uVar10 = *(int *)(param_1 + 0x1c) * iVar17;
          uVar4 = uVar10 + 0x3f;
          if (-1 < (int)uVar10) {
            uVar4 = uVar10;
          }
          uVar13 = (int)uVar10 % 0x40;
          uVar5 = uVar13 + 0x1f;
          if (-1 < (int)uVar13) {
            uVar5 = uVar13;
          }
          uVar14 = (int)uVar10 % 0x20;
          uVar13 = uVar14 + 0xf;
          if (-1 < (int)uVar14) {
            uVar13 = uVar14;
          }
          param_3 = puVar15 + 2;
          puVar2 = (undefined8 *)
                   (param_5 + (int)((uVar16 & 6) << 5 | (uVar16 & 1) << 4 |
                                   (iVar9 * iVar8 + (uVar16 - iVar7 * iVar6 >> 3)) * 0x200) +
                   (long)(int)((int)uVar10 % 0x10 + iVar18 * (uVar4 >> 6) * 0x200 +
                               (uVar5 & 0x1fffffe0) * 8 + (uVar13 & 0x7ffffff0) * 2));
          *puVar2 = *puVar15;
          puVar2[1] = puVar15[1];
          if (iVar11 + -1 == iVar17) break;
          iVar18 = *piVar3;
          iVar17 = iVar17 + 1;
          puVar15 = param_3;
        }
        uVar16 = uVar16 + 1;
      } while (uVar16 != uVar12);
    }
  }
  else {
    if (*(int *)(param_1 + 0x1c) != 8) {
      return 0;
    }
    if ((0 < (int)uVar12) && (0 < iVar11)) {
      lVar1 = param_1 + (long)(int)param_2 * 4;
      uVar16 = 0;
      piVar3 = (int *)(lVar1 + 0x60);
      do {
        iVar18 = *piVar3;
        iVar6 = iVar18 * 8;
        iVar7 = 0;
        if (iVar6 != 0) {
          iVar7 = (int)uVar16 / iVar6;
        }
        iVar8 = *(int *)(lVar1 + 0xa0);
        iVar17 = 0;
        iVar9 = iVar7 * iVar18;
        puVar15 = param_3;
        while( true ) {
          uVar10 = *(int *)(param_1 + 0x1c) * iVar17;
          uVar4 = uVar10 + 0x3f;
          if (-1 < (int)uVar10) {
            uVar4 = uVar10;
          }
          uVar13 = (int)uVar10 % 0x40;
          uVar5 = uVar13 + 0x1f;
          if (-1 < (int)uVar13) {
            uVar5 = uVar13;
          }
          uVar14 = (int)uVar10 % 0x20;
          param_3 = puVar15 + 1;
          uVar13 = uVar14 + 0xf;
          if (-1 < (int)uVar14) {
            uVar13 = uVar14;
          }
          *(undefined8 *)
           (param_5 + (int)((uVar16 & 6) << 5 | (uVar16 & 1) << 4 |
                           (iVar9 * iVar8 + (uVar16 - iVar7 * iVar6 >> 3)) * 0x200) +
           (long)(int)((int)uVar10 % 0x10 + iVar18 * (uVar4 >> 6) * 0x200 + (uVar5 & 0x1fffffe0) * 8
                      + (uVar13 & 0x7ffffff0) * 2)) = *puVar15;
          if (iVar11 + -1 == iVar17) break;
          iVar18 = *piVar3;
          iVar17 = iVar17 + 1;
          puVar15 = param_3;
        }
        uVar16 = uVar16 + 1;
      } while (uVar16 != uVar12);
    }
  }
  return 1;
}



undefined8 FUN_71000110b0(undefined8 *param_1,int param_2)

{
  undefined8 uVar1;
  byte local_28 [8];
  
  FUN_7100011124(local_28);
  if ((param_2 == 0) || ((local_28[0] & 1) != 0)) {
    uVar1 = 0;
    if (param_1 != (undefined8 *)0x0) {
      *param_1 = 0;
      return uVar1;
    }
  }
  else {
    uVar1 = 0x80000005;
    if (param_1 != (undefined8 *)0x0) {
      *param_1 = "ASIMD";
    }
  }
  return uVar1;
}



void FUN_7100011124(byte *param_1)

{
  *param_1 = *param_1 | 0x3f;
  return;
}



ushort FUN_7100011140(uint param_1,long param_2,int param_3)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  ushort uVar3;
  
  puVar1 = DAT_7103a69338;
  DAT_7103a69338[6] = 0;
  puVar1[7] = 0;
  puVar1[4] = 0;
  puVar1[5] = 0;
  puVar2 = DAT_7103a69340;
  puVar1[2] = 0;
  puVar1[3] = 0;
  *puVar1 = 0;
  puVar1[1] = 0;
  *puVar2 = 0;
  uVar3 = FUN_7100015570(0,param_1,0,param_2,param_3);
  return uVar3;
}



void FUN_7100011190(uint param_1,short *param_2,uint param_3)

{
  FUN_7100014980(param_1,(char *)0x0,param_2,param_3);
  return;
}



undefined4 FUN_71000111a0(long param_1,uint param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = FUN_71000111d0(param_1,param_2);
  *DAT_7103a69340 = piVar1;
  uVar2 = 0xfffffffd;
  if (piVar1 != (int *)0x0) {
    uVar2 = 1;
  }
  return uVar2;
}



int * FUN_71000111d0(long param_1,uint param_2)

{
  byte *pbVar1;
  byte bVar2;
  int iVar3;
  int *piVar4;
  byte *pbVar5;
  auto_branch_710009EA50_0x710009ea60_param_1 *paVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  byte *pbVar9;
  long lVar10;
  byte *pbVar11;
  long lVar12;
  uint uVar13;
  byte *pbVar14;
  ulong uVar15;
  long lVar16;
  undefined1 auStack_27c [512];
  int local_7c;
  byte *local_78;
  int local_6c [3];
  
  local_7c = 0;
  if (param_1 == 0) {
    return (int *)0x0;
  }
  if ((int)param_2 < 1) {
    return (int *)0x0;
  }
  piVar4 = (int *)FUN_710225e120(0x10);
  if (piVar4 == (int *)0x0) {
    return (int *)0x0;
  }
  *piVar4 = 0;
  uVar15 = (ulong)(param_2 * 2 + 0xb);
  local_6c[0] = param_2 * 2 + 10;
  piVar4[2] = 0;
  piVar4[3] = 0;
  local_78 = (byte *)FUN_710225e120(uVar15);
  thunk_EXT_FUN_02e95df0(local_78,0,uVar15);
  FUN_7100012f80(param_1,param_2,(long *)&local_78,local_6c,(int *)0x0,(uint *)*DAT_7103a69340);
  local_78[local_6c[0]] = 0;
  if (local_6c[0] < 1) goto LAB_7100011550;
  iVar3 = branch_71000E16D0_0x710009ece0((long)local_78,2,local_6c[0]);
  pbVar9 = local_78;
  if (((iVar3 != 0) && (local_78 != (byte *)0x0)) && (-1 < local_6c[0])) {
    uVar15 = 0;
    pbVar1 = local_78 + local_6c[0];
    pbVar14 = local_78;
    do {
      lVar12 = (long)pbVar1 - (long)pbVar14;
      bVar2 = *pbVar14;
      pbVar5 = pbVar14 + 1;
      pbVar11 = pbVar14;
      if (bVar2 - 9 < 5 || bVar2 == 0) goto LAB_7100011310;
      while (pbVar14 = pbVar5, uVar13 = (uint)bVar2, pbVar5 = pbVar14, uVar13 == 0x20) {
LAB_7100011310:
        do {
          if (lVar12 == 0) goto LAB_7100011364;
          lVar12 = lVar12 + -1;
          pbVar11 = pbVar11 + 1;
          bVar2 = *pbVar11;
          pbVar5 = pbVar5 + 1;
        } while (bVar2 - 9 < 5 || bVar2 == 0);
      }
      if (0xd < uVar13) goto LAB_7100011318;
      while (pbVar5 = pbVar14, (1 << (ulong)(uVar13 & 0x1f) & 0x2401U) == 0) {
LAB_7100011318:
        do {
          if (pbVar1 <= pbVar5 + -1) goto LAB_7100011364;
          pbVar14 = pbVar5 + 1;
          bVar2 = *pbVar5;
          uVar13 = (uint)bVar2;
          pbVar5 = pbVar14;
        } while (0xd < bVar2);
      }
      uVar15 = (ulong)((int)uVar15 + 1);
      pbVar14[-1] = 0;
    } while (pbVar14 <= pbVar1);
    goto LAB_7100011368;
  }
LAB_710001154c:
  FUN_710225e140(pbVar9);
LAB_7100011550:
  FUN_710225e140(piVar4);
  return (int *)0x0;
LAB_7100011364:
  if ((int)uVar15 != 0) {
LAB_7100011368:
    lVar12 = FUN_710225e120(uVar15 << 4);
    pbVar9 = local_78;
    *(long *)(piVar4 + 2) = lVar12;
    if (lVar12 != 0) {
      paVar6 = (auto_branch_710009EA50_0x710009ea60_param_1 *)branch_71000E1680_0x710009ea00();
      lVar12 = 0;
      if ((pbVar9 != (byte *)0x0) && (pbVar9 <= pbVar1)) {
        lVar12 = 0;
        do {
          while( true ) {
            lVar10 = (long)pbVar1 - (long)pbVar9;
            bVar2 = *pbVar9;
            pbVar14 = pbVar9 + 1;
            if (bVar2 - 9 < 5 || bVar2 == 0) goto LAB_71000113f4;
            while (uVar13 = (uint)bVar2, uVar13 == 0x20) {
LAB_71000113f4:
              do {
                if (lVar10 == 0) goto LAB_7100011528;
                lVar10 = lVar10 + -1;
                pbVar9 = pbVar9 + 1;
                bVar2 = *pbVar9;
                pbVar14 = pbVar14 + 1;
              } while (bVar2 - 9 < 5 || bVar2 == 0);
            }
            pbVar5 = pbVar14;
            if (0xd < uVar13) goto LAB_71000113fc;
            while (pbVar5 = pbVar14, (1 << (ulong)(uVar13 & 0x1f) & 0x2401U) == 0) {
LAB_71000113fc:
              do {
                if (pbVar1 <= pbVar5 + -1) goto LAB_7100011528;
                pbVar14 = pbVar5 + 1;
                bVar2 = *pbVar5;
                uVar13 = (uint)bVar2;
                pbVar5 = pbVar14;
              } while (0xd < bVar2);
            }
            pbVar14[-1] = 0;
            uVar7 = branch_71000E1690_0x710009ea50(paVar6,pbVar9,1);
            pbVar9 = pbVar14;
            if ((-1 < (int)uVar7) &&
               (iVar3 = branch_71000E16B0_0x710009eca0((long)paVar6), iVar3 == 2)) break;
LAB_71000114c4:
            if (pbVar1 < pbVar14) goto LAB_7100011528;
          }
          uVar7 = branch_71000E16C0_0x710009ecb0((long)paVar6,0);
          uVar8 = branch_71000E16C0_0x710009ecb0((long)paVar6,1);
          lVar10 = thunk_EXT_FUN_02e95df0(uVar7);
          if ((lVar10 != 4) ||
             ((thunk_EXT_FUN_02e95df0(uVar7,&DAT_71030dad38,&local_7c), iVar3 = local_7c,
              local_7c - 0xf900U < 0xffffe700 ||
              (uVar15 = thunk_EXT_FUN_02e95df0(uVar8), 0x1ff < uVar15)))) goto LAB_71000114c4;
          thunk_EXT_FUN_02e95df0(auStack_27c,uVar8);
          lVar16 = lVar12 * 0x10;
          *(short *)(*(long *)(piVar4 + 2) + lVar16) = (short)iVar3;
          lVar10 = thunk_EXT_FUN_02e95df0(auStack_27c);
          uVar7 = FUN_710225e120(lVar10 + 1);
          *(undefined8 *)(*(long *)(piVar4 + 2) + lVar16 + 8) = uVar7;
          thunk_EXT_FUN_02e95df0(*(undefined8 *)(*(long *)(piVar4 + 2) + lVar16 + 8),auStack_27c);
          lVar12 = lVar12 + 1;
        } while (pbVar14 <= pbVar1);
      }
LAB_7100011528:
      FUN_710225e140(local_78);
      branch_71000E16A0_0x710009ec50((long)paVar6);
      if (0 < (int)lVar12) {
        *piVar4 = (int)lVar12;
        return piVar4;
      }
      pbVar9 = *(byte **)(piVar4 + 2);
      if (*(byte **)(piVar4 + 2) == (byte *)0x0) goto LAB_7100011550;
    }
  }
  goto LAB_710001154c;
}



uint FUN_71000115a0(uint param_1,long param_2,uint param_3,long param_4,uint *param_5,int *param_6,
                   undefined8 *param_7,int *param_8,undefined8 *param_9,uint param_10,uint param_11,
                   uint param_12,undefined4 param_13,int param_14,uint param_15,uint param_16,
                   uint param_17,uint param_18)

{
  bool bVar1;
  short *psVar2;
  long *plVar3;
  uint uVar4;
  uint uVar5;
  long lVar6;
  int iVar7;
  long lVar8;
  int iVar9;
  ulong uVar10;
  long lVar11;
  long lVar12;
  long lVar13;
  int local_84;
  auto_FUN_71000115a0_local_80 *local_80;
  auto_FUN_71000115a0_local_78 *local_78;
  char *local_70 [2];
  
  local_78 = (auto_FUN_71000115a0_local_78 *)0x0;
  local_70[0] = (char *)0x0;
  if ((param_2 != 0) && (param_3 == 0xffffffff)) {
    param_3 = thunk_EXT_FUN_02e95df0(param_2);
  }
  if (param_11 < 8) {
    if (param_2 != 0) {
      local_84 = param_3 * 2 + 10;
      lVar13 = (long)local_84;
      local_70[0] = (char *)FUN_710225e120(lVar13);
      thunk_EXT_FUN_02e95df0(local_70[0],0,lVar13);
      if (param_10 == 0) {
        plVar3 = (long *)(&DAT_7103e3c070 + (ulong)param_11 * 8);
        if (*plVar3 != 0) {
          FUN_710225e140(*plVar3);
          *plVar3 = 0;
        }
        lVar6 = FUN_710225e120(lVar13 << 2);
        *plVar3 = lVar6;
        thunk_EXT_FUN_02e95df0(lVar6,0,lVar13 << 2);
        FUN_7100012a00(param_2,param_3,(long *)local_70,&local_84,plVar3,(int *)0x0,
                       (uint *)*DAT_7103a69340);
      }
      else {
        FUN_7100012f80(param_2,param_3,(long *)local_70,&local_84,(int *)0x0,(uint *)*DAT_7103a69340
                      );
      }
    }
    FUN_71000155a0('\0');
    uVar5 = FUN_71000e16e0(param_1,local_70[0],param_4,param_5,(uint *)(ulong)param_10,
                           (uint *)(ulong)param_11,param_12,&local_78,&local_80,param_13,param_14,
                           param_15,param_16,param_17,param_18);
    if (param_6 != (int *)0x0) {
      *param_6 = 0;
    }
    if (param_8 != (int *)0x0) {
      *param_8 = 0;
    }
    lVar13 = DAT_7103a69348;
    if (uVar5 == 0) {
      if ((param_6 != (int *)0x0) && (0 < (int)*param_5)) {
        lVar6 = (long)*(int *)(local_78 + 2);
        uVar4 = *(uint *)((long)&local_78[3].field_0x4_r + 4);
        uVar10 = (ulong)uVar4;
        if (*(int *)(local_78 + 2) <= (int)uVar4) {
          do {
            iVar9 = (int)uVar10;
            if (((*(int *)((long)&local_78[2].field_0x4_r + 4) == 0) &&
                ((int)local_78[2].field_0x4_r == 0)) && (*(int *)(local_78 + 3) == 0)) {
              *param_6 = *param_6 +
                         (int)*(char *)(lVar13 + (long)*(short *)(*(long *)(*(long *)local_78 +
                                                                            lVar6 * 0x30 + 8) + 4) *
                                                 3);
              iVar9 = *(int *)((long)&local_78[3].field_0x4_r + 4);
              iVar7 = *(int *)(local_78 + 2);
              if (iVar7 == iVar9) goto LAB_710001186c;
LAB_7100011900:
              if (iVar7 == (int)lVar6) {
                lVar8 = *(long *)local_78;
                iVar9 = *(int *)((long)&local_78[2].field_0x4_r + 4);
                if (iVar9 + 1 < (int)*(short *)(lVar8 + lVar6 * 0x30)) {
                  iVar7 = *param_6;
                  lVar11 = (long)iVar9 + 1;
                  lVar12 = (long)iVar9 * 8 + 0xc;
                  do {
                    lVar11 = lVar11 + 1;
                    psVar2 = (short *)(*(long *)(lVar8 + lVar6 * 0x30 + 8) + lVar12);
                    lVar12 = lVar12 + 8;
                    iVar7 = iVar7 + *(char *)(lVar13 + (long)*psVar2 * 3);
                    *param_6 = iVar7;
                    lVar8 = *(long *)local_78;
                  } while (lVar11 < *(short *)(lVar8 + lVar6 * 0x30));
                }
              }
              else if (iVar9 == (int)lVar6) {
                if (-1 < (int)local_78[4].field_0x4_r) {
                  iVar9 = *param_6;
                  lVar11 = 4;
                  lVar8 = -1;
                  do {
                    lVar8 = lVar8 + 1;
                    psVar2 = (short *)(*(long *)(*(long *)local_78 + lVar6 * 0x30 + 8) + lVar11);
                    lVar11 = lVar11 + 8;
                    iVar9 = iVar9 + *(char *)(lVar13 + (long)*psVar2 * 3);
                    *param_6 = iVar9;
                  } while (lVar8 < (int)local_78[4].field_0x4_r);
                }
              }
              else {
                lVar8 = *(long *)local_78;
                if (0 < *(short *)(lVar8 + lVar6 * 0x30)) {
                  iVar9 = *param_6;
                  lVar11 = 0;
                  lVar12 = 4;
                  do {
                    lVar11 = lVar11 + 1;
                    psVar2 = (short *)(*(long *)(lVar8 + lVar6 * 0x30 + 8) + lVar12);
                    lVar12 = lVar12 + 8;
                    iVar9 = iVar9 + *(char *)(lVar13 + (long)*psVar2 * 3);
                    *param_6 = iVar9;
                    lVar8 = *(long *)local_78;
                  } while (lVar11 < *(short *)(lVar8 + lVar6 * 0x30));
                }
              }
            }
            else {
              iVar7 = *(int *)(local_78 + 2);
              if (iVar7 != iVar9) goto LAB_7100011900;
LAB_710001186c:
              iVar9 = *(int *)((long)&local_78[2].field_0x4_r + 4);
              lVar8 = (long)iVar9;
              if (iVar9 < (int)local_78[4].field_0x4_r) {
                iVar9 = *param_6;
                lVar11 = lVar8 * 8 + 0xc;
                do {
                  lVar8 = lVar8 + 1;
                  psVar2 = (short *)(*(long *)(*(long *)local_78 + lVar6 * 0x30 + 8) + lVar11);
                  lVar11 = lVar11 + 8;
                  iVar9 = iVar9 + *(char *)(lVar13 + (long)*psVar2 * 3);
                  *param_6 = iVar9;
                } while (lVar8 < (int)local_78[4].field_0x4_r);
              }
            }
            uVar10 = (ulong)*(int *)((long)&local_78[3].field_0x4_r + 4);
            bVar1 = lVar6 < (long)uVar10;
            lVar6 = lVar6 + 1;
          } while (bVar1);
        }
      }
      if (((param_8 != (int *)0x0) && (0 < *(int *)local_80)) &&
         (*(int *)&local_80[2].field_0x2 != -1)) {
        *param_8 = (*(int *)&local_80[2].field_0x2 - *(int *)((long)&local_80[1].field_0x5_r + 2)) +
                   1;
      }
      *param_7 = local_78;
      *param_9 = local_80;
    }
    if (local_70[0] != (char *)0x0) {
      FUN_710225e140(local_70[0]);
    }
  }
  else {
    uVar5 = 0xfffffffe;
  }
  return uVar5;
}



int FUN_7100011a40(auto_FUN_7100011a40_param_1 *param_1,uint param_2,long param_3,int param_4)

{
  bool bVar1;
  long lVar2;
  int *piVar3;
  int *piVar4;
  int *piVar5;
  uint uVar6;
  long lVar7;
  long lVar8;
  ulong uVar9;
  long lVar10;
  int *piVar11;
  long lVar12;
  ulong uVar13;
  long lVar14;
  char *pcVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  short *psVar19;
  long lVar20;
  long lVar21;
  ulong uVar22;
  long lVar23;
  long lVar24;
  
  lVar8 = DAT_7103a69348;
  lVar7 = DAT_7103a69338;
  iVar17 = 0;
  if ((param_1 != (auto_FUN_7100011a40_param_1 *)0x0) && (0 < param_4)) {
    if (param_2 < 8) {
      uVar22 = (ulong)*(uint *)(param_1 + 4);
      if ((int)*(uint *)(param_1 + 4) < *(int *)&param_1[2].field_0x2) {
        return 0;
      }
      iVar18 = 0;
      iVar17 = *(int *)((long)&param_1[1].field_0x3_r + 6);
      lVar21 = (ulong)param_2 * 8;
      lVar20 = (long)*(int *)&param_1[2].field_0x2;
      do {
        if (*(int *)&param_1[2].field_0x2 == (int)uVar22) {
          uVar6 = *(uint *)((long)&param_1[2].field_0x3_r + 7);
          uVar22 = (ulong)uVar6;
          if (uVar6 == 0) {
            if ((*(int *)((long)&param_1[2].field_0x3_r + 3) != 0) ||
               ((int)param_1[3].field_0x3_r != 0)) goto LAB_7100011c90;
            piVar11 = (int *)(param_3 + (long)iVar18 * 0x10);
            lVar24 = lVar20 * 0x30;
            lVar23 = (long)iVar18;
            *piVar11 = iVar17;
            piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar24 + 0x14) * 4);
            piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar24 + 0x18) * 4);
            lVar10 = (long)*(short *)(*(long *)(*(long *)param_1 + lVar24 + 8) + 4) * 3;
            if (*(char *)(lVar8 + lVar10) == '\x02') {
              lVar14 = lVar23 * 0x10;
              lVar23 = lVar23 + 1;
              *(short *)(param_3 + lVar14 + 0xc) = (short)*(char *)(lVar8 + lVar10 + 1);
              piVar11 = (int *)(param_3 + lVar23 * 0x10);
              iVar16 = **(int **)(*(long *)param_1 + lVar24 + 8);
              if (iVar16 < 0) {
                iVar16 = iVar16 + 1;
              }
              *piVar11 = iVar17 + (iVar16 >> 1);
              piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar24 + 0x14) * 4);
              piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar24 + 0x18) * 4);
              iVar16 = 2;
              pcVar15 = (char *)(lVar8 + (long)*(short *)(*(long *)(*(long *)param_1 + lVar24 + 8) +
                                                         4) * 3 + 2);
LAB_7100012370:
              iVar18 = iVar18 + iVar16;
              *(short *)(param_3 + lVar23 * 0x10 + 0xc) = (short)*pcVar15;
            }
            else if (*(char *)(lVar8 + lVar10) == '\x01') {
              iVar16 = 1;
              pcVar15 = (char *)(lVar8 + lVar10 + 1);
              goto LAB_7100012370;
            }
            iVar17 = **(int **)(*(long *)param_1 + lVar20 * 0x30 + 8) + iVar17;
            uVar6 = *(uint *)((long)&param_1[2].field_0x3_r + 7);
            uVar22 = (ulong)uVar6;
            if (*(int *)((long)&param_1[4].field_0x3_r + 5) <= (int)uVar6) goto LAB_7100011ab0;
          }
          else {
            if (-1 < (int)uVar6) {
LAB_7100011c90:
              lVar23 = *(long *)(*(long *)param_1 + lVar20 * 0x30 + 8);
              if (uVar6 < 3) {
                uVar13 = 0;
              }
              else {
                uVar13 = 0;
                piVar11 = (int *)(lVar23 + 0x10);
                do {
                  piVar4 = piVar11 + -4;
                  uVar13 = uVar13 + 4;
                  piVar5 = piVar11 + -2;
                  iVar16 = *piVar11;
                  piVar3 = piVar11 + 2;
                  piVar11 = piVar11 + 8;
                  iVar17 = *piVar3 + iVar16 + *piVar5 + *piVar4 + iVar17;
                } while ((uVar22 + 1 & 0xfffffffc) != uVar13);
              }
              uVar9 = uVar22 + 1 & 3;
              if (uVar9 != 0) {
                piVar11 = (int *)(lVar23 + uVar13 * 8);
                do {
                  uVar9 = uVar9 - 1;
                  iVar17 = *piVar11 + iVar17;
                  piVar11 = piVar11 + 2;
                } while (uVar9 != 0);
              }
            }
            iVar17 = iVar17 - *(int *)((long)&param_1[2].field_0x3_r + 3);
            if (*(int *)((long)&param_1[4].field_0x3_r + 5) <= (int)uVar6) goto LAB_7100011ab0;
          }
          lVar23 = (long)(int)uVar22;
          uVar22 = -(uVar22 >> 0x1f) & 0xfffffff800000000 | uVar22 << 3;
          do {
            piVar11 = (int *)(param_3 + (long)iVar18 * 0x10);
            lVar14 = lVar20 * 0x30;
            lVar10 = (long)iVar18;
            *piVar11 = iVar17;
            piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar14 + 0x14) * 4);
            piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar14 + 0x18) * 4);
            lVar24 = (long)*(short *)(*(long *)(*(long *)param_1 + lVar14 + 8) + uVar22 + 0xc) * 3;
            if (*(char *)(lVar8 + lVar24) == '\x02') {
              lVar12 = lVar10 * 0x10;
              lVar10 = lVar10 + 1;
              *(short *)(param_3 + lVar12 + 0xc) = (short)*(char *)(lVar8 + lVar24 + 1);
              piVar11 = (int *)(param_3 + lVar10 * 0x10);
              iVar16 = *(int *)(*(long *)(*(long *)param_1 + lVar14 + 8) + uVar22 + 8);
              if (iVar16 < 0) {
                iVar16 = iVar16 + 1;
              }
              *piVar11 = iVar17 + (iVar16 >> 1);
              piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar14 + 0x14) * 4);
              piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar14 + 0x18) * 4);
              iVar16 = 2;
              pcVar15 = (char *)(lVar8 + (long)*(short *)(*(long *)(*(long *)param_1 + lVar14 + 8) +
                                                          uVar22 + 0xc) * 3 + 2);
LAB_7100011dc4:
              iVar18 = iVar18 + iVar16;
              *(short *)(param_3 + lVar10 * 0x10 + 0xc) = (short)*pcVar15;
            }
            else if (*(char *)(lVar8 + lVar24) == '\x01') {
              iVar16 = 1;
              pcVar15 = (char *)(lVar8 + lVar24 + 1);
              goto LAB_7100011dc4;
            }
            lVar23 = lVar23 + 1;
            lVar10 = *(long *)(*(long *)param_1 + lVar20 * 0x30 + 8) + uVar22;
            uVar22 = uVar22 + 8;
            iVar17 = *(int *)(lVar10 + 8) + iVar17;
          } while (lVar23 < *(int *)((long)&param_1[4].field_0x3_r + 5));
        }
        else if (*(int *)&param_1[2].field_0x2 == (int)lVar20) {
          uVar6 = *(uint *)((long)&param_1[2].field_0x3_r + 7);
          uVar22 = (ulong)uVar6;
          if (uVar6 == 0) {
            if ((*(int *)((long)&param_1[2].field_0x3_r + 3) != 0) ||
               ((int)param_1[3].field_0x3_r != 0)) {
              lVar10 = *(long *)param_1;
              lVar23 = *(long *)(lVar10 + lVar20 * 0x30 + 8);
LAB_7100011b0c:
              uVar13 = 0;
              goto LAB_7100012050;
            }
            piVar11 = (int *)(param_3 + (long)iVar18 * 0x10);
            lVar24 = lVar20 * 0x30;
            lVar23 = (long)iVar18;
            *piVar11 = iVar17;
            piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar24 + 0x14) * 4);
            piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar24 + 0x18) * 4);
            lVar10 = (long)*(short *)(*(long *)(*(long *)param_1 + lVar24 + 8) + 4) * 3;
            if (*(char *)(lVar8 + lVar10) == '\x02') {
              lVar14 = lVar23 * 0x10;
              lVar23 = lVar23 + 1;
              *(short *)(param_3 + lVar14 + 0xc) = (short)*(char *)(lVar8 + lVar10 + 1);
              piVar11 = (int *)(param_3 + lVar23 * 0x10);
              iVar16 = **(int **)(*(long *)param_1 + lVar24 + 8);
              if (iVar16 < 0) {
                iVar16 = iVar16 + 1;
              }
              *piVar11 = iVar17 + (iVar16 >> 1);
              piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar24 + 0x14) * 4);
              piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar24 + 0x18) * 4);
              iVar16 = 2;
              pcVar15 = (char *)(lVar8 + (long)*(short *)(*(long *)(*(long *)param_1 + lVar24 + 8) +
                                                         4) * 3 + 2);
LAB_7100012430:
              iVar18 = iVar18 + iVar16;
              *(short *)(param_3 + lVar23 * 0x10 + 0xc) = (short)*pcVar15;
            }
            else if (*(char *)(lVar8 + lVar10) == '\x01') {
              iVar16 = 1;
              pcVar15 = (char *)(lVar8 + lVar10 + 1);
              goto LAB_7100012430;
            }
            iVar17 = **(int **)(*(long *)param_1 + lVar20 * 0x30 + 8) + iVar17;
            uVar6 = *(uint *)((long)&param_1[2].field_0x3_r + 7);
            uVar22 = (ulong)uVar6;
            if ((int)*(short *)(*(long *)param_1 + lVar20 * 0x30) <= (int)(uVar6 + 1))
            goto LAB_7100011ab0;
          }
          else {
            lVar10 = *(long *)param_1;
            if (-1 < (int)uVar6) {
              lVar23 = *(long *)(lVar10 + lVar20 * 0x30 + 8);
              if (uVar6 < 3) goto LAB_7100011b0c;
              uVar13 = 0;
              piVar11 = (int *)(lVar23 + 0x10);
              do {
                piVar4 = piVar11 + -4;
                uVar13 = uVar13 + 4;
                piVar5 = piVar11 + -2;
                iVar16 = *piVar11;
                piVar3 = piVar11 + 2;
                piVar11 = piVar11 + 8;
                iVar17 = *piVar3 + iVar16 + *piVar5 + *piVar4 + iVar17;
              } while ((uVar22 + 1 & 0xfffffffc) != uVar13);
LAB_7100012050:
              uVar9 = uVar22 + 1 & 3;
              if (uVar9 != 0) {
                piVar11 = (int *)(lVar23 + uVar13 * 8);
                do {
                  uVar9 = uVar9 - 1;
                  iVar17 = *piVar11 + iVar17;
                  piVar11 = piVar11 + 2;
                } while (uVar9 != 0);
              }
            }
            iVar17 = iVar17 - *(int *)((long)&param_1[2].field_0x3_r + 3);
            if ((int)*(short *)(lVar10 + lVar20 * 0x30) <= (int)(uVar6 + 1)) goto LAB_7100011ab0;
          }
          uVar13 = -(uVar22 >> 0x1f) & 0xfffffff800000000 | uVar22 << 3;
          lVar23 = (long)(int)uVar22 + 1;
          do {
            piVar11 = (int *)(param_3 + (long)iVar18 * 0x10);
            lVar14 = lVar20 * 0x30;
            lVar10 = (long)iVar18;
            *piVar11 = iVar17;
            piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar14 + 0x14) * 4);
            piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar14 + 0x18) * 4);
            lVar24 = (long)*(short *)(*(long *)(*(long *)param_1 + lVar14 + 8) + uVar13 + 0xc) * 3;
            if (*(char *)(lVar8 + lVar24) == '\x02') {
              lVar12 = lVar10 * 0x10;
              lVar10 = lVar10 + 1;
              *(short *)(param_3 + lVar12 + 0xc) = (short)*(char *)(lVar8 + lVar24 + 1);
              piVar11 = (int *)(param_3 + lVar10 * 0x10);
              iVar16 = *(int *)(*(long *)(*(long *)param_1 + lVar14 + 8) + uVar13 + 8);
              if (iVar16 < 0) {
                iVar16 = iVar16 + 1;
              }
              *piVar11 = iVar17 + (iVar16 >> 1);
              piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar14 + 0x14) * 4);
              piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar14 + 0x18) * 4);
              iVar16 = 2;
              pcVar15 = (char *)(lVar8 + (long)*(short *)(*(long *)(*(long *)param_1 + lVar14 + 8) +
                                                          uVar13 + 0xc) * 3 + 2);
LAB_7100012134:
              iVar18 = iVar18 + iVar16;
              *(short *)(param_3 + lVar10 * 0x10 + 0xc) = (short)*pcVar15;
            }
            else if (*(char *)(lVar8 + lVar24) == '\x01') {
              iVar16 = 1;
              pcVar15 = (char *)(lVar8 + lVar24 + 1);
              goto LAB_7100012134;
            }
            lVar23 = lVar23 + 1;
            psVar19 = (short *)(*(long *)param_1 + lVar20 * 0x30);
            lVar10 = *(long *)(psVar19 + 4) + uVar13;
            uVar13 = uVar13 + 8;
            iVar17 = *(int *)(lVar10 + 8) + iVar17;
          } while (lVar23 < *psVar19);
        }
        else if ((int)uVar22 == (int)lVar20) {
          if (-1 < *(int *)((long)&param_1[4].field_0x3_r + 5)) {
            lVar10 = 0;
            lVar23 = -1;
            do {
              piVar11 = (int *)(param_3 + (long)iVar18 * 0x10);
              lVar12 = lVar20 * 0x30;
              lVar24 = (long)iVar18;
              *piVar11 = iVar17;
              piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar12 + 0x14) * 4);
              piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar12 + 0x18) * 4);
              lVar14 = (long)*(short *)(*(long *)(*(long *)param_1 + lVar12 + 8) + lVar10 + 4) * 3;
              if (*(char *)(lVar8 + lVar14) == '\x02') {
                lVar2 = lVar24 * 0x10;
                lVar24 = lVar24 + 1;
                *(short *)(param_3 + lVar2 + 0xc) = (short)*(char *)(lVar8 + lVar14 + 1);
                piVar11 = (int *)(param_3 + lVar24 * 0x10);
                iVar16 = *(int *)(*(long *)(*(long *)param_1 + lVar12 + 8) + lVar10);
                if (iVar16 < 0) {
                  iVar16 = iVar16 + 1;
                }
                *piVar11 = iVar17 + (iVar16 >> 1);
                piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                     (long)*(int *)(*(long *)param_1 + lVar12 + 0x14) * 4);
                piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                     (long)*(int *)(*(long *)param_1 + lVar12 + 0x18) * 4);
                iVar16 = 2;
                pcVar15 = (char *)(lVar8 + (long)*(short *)(*(long *)(*(long *)param_1 + lVar12 + 8)
                                                            + lVar10 + 4) * 3 + 2);
LAB_7100011bc0:
                iVar18 = iVar18 + iVar16;
                *(short *)(param_3 + lVar24 * 0x10 + 0xc) = (short)*pcVar15;
              }
              else if (*(char *)(lVar8 + lVar14) == '\x01') {
                iVar16 = 1;
                pcVar15 = (char *)(lVar8 + lVar14 + 1);
                goto LAB_7100011bc0;
              }
              lVar23 = lVar23 + 1;
              piVar11 = (int *)(*(long *)(*(long *)param_1 + lVar20 * 0x30 + 8) + lVar10);
              lVar10 = lVar10 + 8;
              iVar17 = *piVar11 + iVar17;
            } while (lVar23 < *(int *)((long)&param_1[4].field_0x3_r + 5));
          }
        }
        else if (0 < *(short *)(*(long *)param_1 + lVar20 * 0x30)) {
          lVar10 = 0;
          lVar23 = 0;
          do {
            piVar11 = (int *)(param_3 + (long)iVar18 * 0x10);
            lVar12 = lVar20 * 0x30;
            lVar24 = (long)iVar18;
            *piVar11 = iVar17;
            piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar12 + 0x14) * 4);
            piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                 (long)*(int *)(*(long *)param_1 + lVar12 + 0x18) * 4);
            lVar14 = (long)*(short *)(*(long *)(*(long *)param_1 + lVar12 + 8) + lVar10 + 4) * 3;
            if (*(char *)(lVar8 + lVar14) == '\x02') {
              lVar2 = lVar24 * 0x10;
              lVar24 = lVar24 + 1;
              *(short *)(param_3 + lVar2 + 0xc) = (short)*(char *)(lVar8 + lVar14 + 1);
              piVar11 = (int *)(param_3 + lVar24 * 0x10);
              iVar16 = *(int *)(*(long *)(*(long *)param_1 + lVar12 + 8) + lVar10);
              if (iVar16 < 0) {
                iVar16 = iVar16 + 1;
              }
              *piVar11 = iVar17 + (iVar16 >> 1);
              piVar11[1] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar12 + 0x14) * 4);
              piVar11[2] = *(int *)(*(long *)(lVar7 + lVar21) +
                                   (long)*(int *)(*(long *)param_1 + lVar12 + 0x18) * 4);
              iVar16 = 2;
              pcVar15 = (char *)(lVar8 + (long)*(short *)(*(long *)(*(long *)param_1 + lVar12 + 8) +
                                                          lVar10 + 4) * 3 + 2);
LAB_7100011f2c:
              iVar18 = iVar18 + iVar16;
              *(short *)(param_3 + lVar24 * 0x10 + 0xc) = (short)*pcVar15;
            }
            else if (*(char *)(lVar8 + lVar14) == '\x01') {
              iVar16 = 1;
              pcVar15 = (char *)(lVar8 + lVar14 + 1);
              goto LAB_7100011f2c;
            }
            lVar23 = lVar23 + 1;
            psVar19 = (short *)(*(long *)param_1 + lVar20 * 0x30);
            piVar11 = (int *)(*(long *)(psVar19 + 4) + lVar10);
            lVar10 = lVar10 + 8;
            iVar17 = *piVar11 + iVar17;
          } while (lVar23 < *psVar19);
        }
LAB_7100011ab0:
        uVar22 = (ulong)*(int *)(param_1 + 4);
        bVar1 = (long)uVar22 <= lVar20;
        lVar20 = lVar20 + 1;
        if (bVar1) {
          return iVar18;
        }
      } while( true );
    }
    iVar17 = -2;
  }
  return iVar17;
}



ulong FUN_7100012480(long param_1,long param_2,int param_3)

{
  int iVar1;
  long lVar2;
  ulong uVar3;
  long lVar4;
  
  uVar3 = 0;
  if ((param_1 != 0) && (0 < param_3)) {
    iVar1 = *(int *)(param_1 + 0x10);
    if (*(int *)(param_1 + 0x14) < iVar1) {
      return 0;
    }
    uVar3 = 0;
    lVar2 = param_2 + 4;
    lVar4 = (long)iVar1 * 0x210;
    do {
      uVar3 = uVar3 + 1;
      *(undefined4 *)(lVar2 + -4) = *(undefined4 *)(*(long *)(param_1 + 8) + lVar4);
      lVar2 = thunk_EXT_FUN_02e95df0(lVar2,*(long *)(param_1 + 8) + lVar4 + 0xc);
      lVar2 = lVar2 + 0x204;
      lVar4 = lVar4 + 0x210;
    } while ((long)((long)iVar1 + -1 + uVar3) < (long)*(int *)(param_1 + 0x14));
  }
  return uVar3 & 0xffffffff;
}



undefined4 FUN_7100012530(undefined4 param_1,long param_2,uint param_3,char *param_4,int param_5)

{
  undefined4 uVar1;
  long lVar2;
  int local_4c;
  long local_48;
  
  local_48 = 0;
  if ((param_2 == 0) || (param_3 != 0xffffffff)) {
    if (param_2 == 0) goto LAB_71000125d8;
  }
  else {
    param_3 = thunk_EXT_FUN_02e95df0(param_2);
  }
  local_4c = param_3 * 2 + 10;
  lVar2 = (long)local_4c;
  local_48 = FUN_710225e120(lVar2);
  thunk_EXT_FUN_02e95df0(local_48,0,lVar2);
  FUN_7100012f80(param_2,param_3,&local_48,&local_4c,(int *)0x0,(uint *)*DAT_7103a69340);
LAB_71000125d8:
  uVar1 = FUN_7100015710(param_1,local_48,(auto_FUN_7100015710_param_3 *)param_4,param_5);
  if (local_48 != 0) {
    FUN_710225e140(local_48);
  }
  return uVar1;
}



int FUN_7100012620(long param_1,uint param_2,long param_3,uint *param_4,int param_5,int param_6,
                  uint param_7,uint param_8)

{
  undefined8 uVar1;
  long lVar2;
  ulong uVar3;
  long lVar4;
  int local_64;
  char *local_48;
  
  local_48 = (char *)0x0;
  if ((param_1 == 0) || (param_2 != 0xffffffff)) {
    if (param_1 == 0) goto LAB_71000126d0;
  }
  else {
    param_2 = thunk_EXT_FUN_02e95df0(param_1);
  }
  local_64 = param_2 * 2 + 10;
  lVar4 = (long)local_64;
  local_48 = (char *)FUN_710225e120(lVar4);
  thunk_EXT_FUN_02e95df0(local_48,0,lVar4);
  FUN_7100012f80(param_1,param_2,(long *)&local_48,&local_64,(int *)0x0,(uint *)*DAT_7103a69340);
LAB_71000126d0:
  FUN_71000155a0('\0');
  FUN_71000e0bd0(local_48,param_3,(int *)param_4,-1,param_6,param_7,param_8);
  lVar4 = FUN_710225e120((long)(int)*param_4 + 1);
  thunk_EXT_FUN_02e95df0(lVar4,0,(long)(int)*param_4 + 1);
  uVar1 = FUN_71000e0bd0(local_48,lVar4,(int *)param_4,1,param_6,param_7,param_8);
  lVar2 = FUN_710225e120((long)(int)*param_4 * 3 + 1);
  uVar3 = FUN_71000127d0(-1,lVar4,*param_4,lVar2);
  *param_4 = (uint)uVar3;
  if (lVar4 != 0) {
    FUN_710225e140(lVar4);
  }
  if (param_5 == 1) {
    thunk_EXT_FUN_02e95df0(param_3,lVar2,(long)(int)*param_4);
  }
  if (lVar2 != 0) {
    FUN_710225e140(lVar2);
  }
  if (local_48 != (char *)0x0) {
    FUN_710225e140(local_48);
  }
  return (int)(short)uVar1;
}



ulong FUN_71000127d0(int param_1,long param_2,uint param_3,long param_4)

{
  undefined1 *puVar1;
  uint uVar2;
  ulong uVar3;
  ulong uVar4;
  long lVar5;
  ulong uVar6;
  ulong local_50;
  long local_48;
  
  if ((param_1 == 0x3a4) || (param_1 == -1)) {
    uVar4 = 0;
    if ((param_2 != 0) && (param_3 != 0)) {
      uVar4 = 0;
      uVar6 = (ulong)param_3;
      local_48 = param_4;
      do {
        uVar2 = (uint)*(byte *)(param_2 + uVar4) << 8;
        if (*(byte *)(param_2 + uVar4) < 0x81) {
          uVar2 = 0;
        }
        else {
          uVar4 = uVar4 + 1;
        }
        FUN_71000133a0(uVar2 | *(byte *)(param_2 + uVar4));
        uVar4 = uVar4 + 1;
      } while (uVar4 < uVar6);
      if (param_4 == 0) {
        uVar4 = (ulong)((int)uVar4 + 1);
      }
      else {
        local_50 = (ulong)(param_3 << 2);
        if (param_1 == -1) {
          uVar3 = 0;
          uVar4 = 0;
          do {
            while( true ) {
              uVar2 = (uint)*(byte *)(param_2 + uVar3) << 8;
              if (*(byte *)(param_2 + uVar3) < 0x81) {
                uVar2 = 0;
              }
              else {
                uVar3 = uVar3 + 1;
              }
              uVar2 = FUN_71000133a0(uVar2 | *(byte *)(param_2 + uVar3));
              if ((uVar2 & 0xffff) == 0xfeff) break;
              lVar5 = (long)(int)local_50;
              FUN_71000133d0(uVar2 & 0xffff,&local_48,&local_50);
              uVar4 = (uVar4 - local_50) + lVar5;
              uVar3 = uVar3 + 1;
              if (uVar6 <= uVar3) goto LAB_71000129d8;
            }
            uVar3 = uVar3 + 2;
          } while (uVar3 < uVar6);
        }
        else if (param_1 == 0x3a4) {
          uVar3 = 0;
          lVar5 = 0;
          uVar4 = 0;
          do {
            while( true ) {
              uVar2 = (uint)*(byte *)(param_2 + uVar3) << 8;
              if (*(byte *)(param_2 + uVar3) < 0x81) {
                uVar2 = 0;
              }
              else {
                uVar3 = uVar3 + 1;
              }
              uVar2 = FUN_71000133a0(uVar2 | *(byte *)(param_2 + uVar3));
              if ((uVar2 & 0xffff) == 0xfeff) break;
              uVar2 = FUN_7100013370(uVar2);
              if (0x80 < (uVar2 >> 8 & 0xff)) {
                *(undefined1 *)(local_48 + lVar5) = (char)(uVar2 >> 8);
                ((undefined1 *)(local_48 + lVar5))[1] = 0;
                lVar5 = lVar5 + 1;
                uVar4 = uVar4 + 1;
              }
              puVar1 = (undefined1 *)(local_48 + lVar5);
              lVar5 = lVar5 + 1;
              *puVar1 = (char)uVar2;
              puVar1[1] = 0;
              uVar4 = uVar4 + 1;
              uVar3 = uVar3 + 1;
              if (uVar6 <= uVar3) goto LAB_71000129d8;
            }
            uVar3 = uVar3 + 2;
          } while (uVar3 < uVar6);
        }
        else {
          uVar4 = 0;
          do {
            uVar2 = (uint)*(byte *)(param_2 + uVar4) << 8;
            if (*(byte *)(param_2 + uVar4) < 0x81) {
              uVar2 = 0;
            }
            else {
              uVar4 = uVar4 + 1;
            }
            uVar2 = FUN_71000133a0(uVar2 | *(byte *)(param_2 + uVar4));
            if ((uVar2 & 0xffff) == 0xfeff) {
              uVar4 = uVar4 + 1;
            }
            uVar4 = uVar4 + 1;
          } while (uVar4 < uVar6);
          uVar4 = 0;
        }
      }
    }
  }
  else {
    uVar4 = 0;
  }
LAB_71000129d8:
  return uVar4 & 0xffffffff;
}



int FUN_7100012a00(long param_1,uint param_2,long *param_3,int *param_4,long *param_5,int *param_6,
                  uint *param_7)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  long lVar6;
  uint uVar7;
  undefined8 uVar8;
  long lVar9;
  int iVar10;
  ulong uVar11;
  ulong uVar12;
  ulong local_78;
  long lStack_70;
  long local_68;
  
  if (param_6 != (int *)0x0) {
    *param_6 = 0;
  }
  iVar2 = 0;
  if ((param_1 != 0) && (param_2 != 0)) {
    uVar7 = 0;
    local_78 = (ulong)param_2;
    lStack_70 = param_1;
    local_68 = param_1;
    do {
      uVar3 = FUN_7100013520(&local_68,&local_78);
      uVar4 = uVar7;
      if (local_78 == 0) break;
      uVar7 = uVar7 + 1;
      uVar4 = param_2;
    } while (param_2 != uVar7);
    if ((uVar4 == 0) && ((uVar3 & 0xfffffffe) == 0xfffe)) {
      iVar2 = 0;
    }
    else {
      if (*param_3 != 0) {
        iVar2 = 0;
        uVar7 = 0;
        uVar11 = 0;
        uVar12 = 0;
        local_78 = (ulong)param_2;
LAB_7100012ae8:
        iVar10 = (int)uVar11;
        iVar1 = (int)local_78;
        uVar4 = FUN_7100013520(&lStack_70,&local_78);
        iVar1 = iVar1 - (int)local_78;
        if (iVar1 != 0) {
          if (uVar4 == 0xefbbbf) {
LAB_7100012ad0:
            *(int *)(*param_5 + uVar12 * 4) = iVar2;
            goto LAB_7100012ad8;
          }
          if (uVar4 == 0xfffe) {
            *(int *)(*param_5 + uVar12 * 4) = iVar2;
            if (param_6 != (int *)0x0) {
              *param_6 = *param_6 + 1;
            }
            goto LAB_7100012ad8;
          }
          if (uVar4 == 0xfeff) goto LAB_7100012ad0;
          if (uVar4 - 0xe000 >> 8 < 0x19) {
            if ((param_7 != (uint *)0x0) && (0 < (int)*param_7)) {
              lVar9 = 0;
LAB_7100012b60:
              if (uVar4 != *(ushort *)(*(long *)(param_7 + 2) + lVar9)) goto code_r0x007100012b6c;
              uVar8 = *(undefined8 *)(*(long *)(param_7 + 2) + lVar9 + 8);
              iVar5 = thunk_EXT_FUN_02e95df0(uVar8);
              uVar4 = iVar10 + iVar5;
              if (*param_4 <= (int)uVar4) {
                uVar3 = iVar10 + 1;
                uVar8 = FUN_710225e120((long)(int)uVar3);
                thunk_EXT_FUN_02e95df0(uVar8,*param_3);
                FUN_710225e140(*param_3);
                lVar6 = FUN_710225e120((long)((*param_4 + iVar5) * 2));
                *param_3 = lVar6;
                thunk_EXT_FUN_02e95df0(lVar6,0,(long)((*param_4 + iVar5) * 2));
                *param_4 = (*param_4 + iVar5) * 2;
                thunk_EXT_FUN_02e95df0(*param_3,uVar8,(long)iVar10);
                FUN_710225e140(uVar8);
                uVar8 = FUN_710225e120(-(ulong)(uVar3 >> 0x1f) & 0xfffffffc00000000 |
                                       (ulong)uVar3 << 2);
                thunk_EXT_FUN_02e95df0(uVar8,*param_5);
                FUN_710225e140(*param_5);
                lVar6 = FUN_710225e120((long)*param_4 << 2);
                *param_5 = lVar6;
                thunk_EXT_FUN_02e95df0(lVar6,0,(long)*param_4 << 2);
                thunk_EXT_FUN_02e95df0
                          (*param_5,uVar8,-(uVar11 >> 0x1f) & 0xfffffffc00000000 | uVar11 << 2);
                FUN_710225e140(uVar8);
                uVar8 = *(undefined8 *)(*(long *)(param_7 + 2) + lVar9 + 8);
              }
              thunk_EXT_FUN_02e95df0(*param_3 + (long)iVar10,uVar8,(long)iVar5);
              *(int *)(*param_5 + uVar12 * 4) = iVar2;
              uVar12 = uVar12 + 1;
              uVar11 = (ulong)uVar4;
              if (uVar12 != 0) {
                for (; uVar12 < (ulong)(long)(int)uVar4; uVar12 = uVar12 + 1) {
                  *(int *)(*param_5 + uVar12 * 4) = iVar2;
                }
                goto joined_r0x007100012bd4;
              }
              goto joined_r0x007100012b80;
            }
          }
          else {
            uVar3 = FUN_7100013370(uVar4);
            if (((uVar3 & 0xffff) == 0) && (uVar4 != 0)) {
              if (param_6 != (int *)0x0) {
                *param_6 = *param_6 + 1;
              }
            }
            else {
              uVar4 = 0xfffffdfe;
              if ((uVar3 & 0xffff) != 0xfffe) {
                uVar4 = uVar3;
              }
              if (*param_4 <= iVar10 + 2) {
                uVar3 = iVar10 + 1;
                uVar8 = FUN_710225e120((long)(int)uVar3);
                thunk_EXT_FUN_02e95df0(uVar8,*param_3);
                FUN_710225e140(*param_3);
                lVar9 = FUN_710225e120((long)(*param_4 * 2 + 4));
                *param_3 = lVar9;
                thunk_EXT_FUN_02e95df0(lVar9,0,(long)(*param_4 * 2 + 4));
                *param_4 = *param_4 * 2 + 4;
                thunk_EXT_FUN_02e95df0(*param_3,uVar8,(long)iVar10);
                FUN_710225e140(uVar8);
                uVar8 = FUN_710225e120(-(ulong)(uVar3 >> 0x1f) & 0xfffffffc00000000 |
                                       (ulong)uVar3 << 2);
                thunk_EXT_FUN_02e95df0(uVar8,*param_5);
                FUN_710225e140(*param_5);
                lVar9 = FUN_710225e120((long)*param_4 << 2);
                *param_5 = lVar9;
                thunk_EXT_FUN_02e95df0(lVar9,0,(long)*param_4 << 2);
                thunk_EXT_FUN_02e95df0
                          (*param_5,uVar8,-(uVar11 >> 0x1f) & 0xfffffffc00000000 | uVar11 << 2);
                FUN_710225e140(uVar8);
              }
              if (0x80 < (uVar4 >> 8 & 0xff)) {
                lVar9 = *param_3;
                *(undefined1 *)(lVar9 + iVar10) = (char)(uVar4 >> 8);
                ((undefined1 *)(lVar9 + iVar10))[1] = 0;
                *(int *)(*param_5 + uVar12 * 4) = iVar2;
                iVar10 = iVar10 + 1;
                uVar12 = uVar12 + 1;
              }
              lVar9 = *param_3;
              *(undefined1 *)(lVar9 + iVar10) = (char)uVar4;
              ((undefined1 *)(lVar9 + iVar10))[1] = 0;
              *(int *)(*param_5 + uVar12 * 4) = iVar2;
              uVar12 = uVar12 + 1;
              uVar11 = (ulong)(iVar10 + 1);
            }
          }
joined_r0x007100012bd4:
          if (local_78 != 0) goto LAB_7100012ad8;
          goto LAB_7100012f3c;
        }
        goto LAB_7100012f44;
      }
      iVar2 = uVar4 + 1;
    }
  }
  return iVar2;
code_r0x007100012b6c:
  lVar9 = lVar9 + 0x10;
  if ((ulong)*param_7 * 0x10 - lVar9 == 0) goto joined_r0x007100012b80;
  goto LAB_7100012b60;
joined_r0x007100012b80:
  if (local_78 == 0) {
LAB_7100012f3c:
    uVar7 = (uVar7 + iVar1) - 1;
    goto LAB_7100012f44;
  }
LAB_7100012ad8:
  uVar7 = uVar7 + iVar1;
  iVar2 = iVar2 + 1;
  if (param_2 <= uVar7) {
LAB_7100012f44:
    if (uVar7 == 0) {
      return 0;
    }
    return (int)uVar12;
  }
  goto LAB_7100012ae8;
}



int FUN_7100012f80(long param_1,uint param_2,long *param_3,int *param_4,int *param_5,uint *param_6)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  long lVar5;
  undefined8 uVar6;
  int iVar7;
  ulong uVar8;
  ulong uVar9;
  long lVar10;
  ulong uVar11;
  long lVar12;
  ulong local_78;
  long local_70;
  long lStack_68;
  
  if (param_5 != (int *)0x0) {
    *param_5 = 0;
  }
  iVar4 = 0;
  if ((param_1 != 0) && (param_2 != 0)) {
    uVar8 = 0;
    uVar11 = (ulong)param_2;
    local_78 = uVar11;
    local_70 = param_1;
    lStack_68 = param_1;
    do {
      uVar1 = FUN_7100013520(&lStack_68,&local_78);
      uVar9 = uVar8;
      if (local_78 == 0) break;
      uVar8 = uVar8 + 1;
      uVar9 = uVar11;
    } while (uVar11 != uVar8);
    if ((uVar9 == 0) && ((uVar1 & 0xfffffffe) == 0xfffe)) {
      iVar4 = 0;
    }
    else if (*param_3 == 0) {
      iVar4 = (int)uVar9 + 1;
    }
    else {
      uVar8 = 0;
      iVar4 = 0;
      lVar12 = 0;
      local_78 = uVar11;
      do {
        uVar9 = local_78;
        iVar3 = (int)lVar12;
        uVar1 = FUN_7100013520(&local_70,&local_78);
        iVar7 = (int)uVar9 - (int)local_78;
        if (iVar7 == 0) break;
        uVar8 = uVar8 + (long)(iVar7 + -1);
        if ((uVar1 != 0xfeff) && (uVar1 != 0xefbbbf)) {
          if (uVar1 == 0xfffe) {
            if (param_5 != (int *)0x0) {
              *param_5 = *param_5 + 1;
            }
          }
          else {
            if (((param_6 != (uint *)0x0) && (uVar1 - 0xe000 >> 8 < 0x19)) && (0 < (int)*param_6)) {
              lVar10 = 0;
              do {
                if (uVar1 == *(ushort *)(*(long *)(param_6 + 2) + lVar10)) {
                  uVar6 = *(undefined8 *)(*(long *)(param_6 + 2) + lVar10 + 8);
                  iVar3 = thunk_EXT_FUN_02e95df0(uVar6);
                  if (*param_4 <= iVar4 + iVar3) {
                    uVar6 = FUN_710225e120((long)(iVar4 + 1));
                    thunk_EXT_FUN_02e95df0(uVar6,*param_3,(long)iVar4);
                    FUN_710225e140(*param_3);
                    lVar5 = FUN_710225e120((long)((*param_4 + iVar3) * 2));
                    *param_3 = lVar5;
                    thunk_EXT_FUN_02e95df0(lVar5,0,(long)((*param_4 + iVar3) * 2));
                    *param_4 = (*param_4 + iVar3) * 2;
                    thunk_EXT_FUN_02e95df0(*param_3,uVar6,(long)iVar4);
                    FUN_710225e140(uVar6);
                    uVar6 = *(undefined8 *)(*(long *)(param_6 + 2) + lVar10 + 8);
                  }
                  thunk_EXT_FUN_02e95df0(*param_3 + (long)iVar4,uVar6,(long)iVar3);
                  lVar12 = iVar3 + lVar12;
                  uVar2 = FUN_7100013370(uVar1);
                  iVar4 = iVar4 + iVar3;
                  goto joined_r0x007100013238;
                }
                lVar10 = lVar10 + 0x10;
              } while ((ulong)*param_6 * 0x10 - lVar10 != 0);
            }
            uVar2 = FUN_7100013370(uVar1);
joined_r0x007100013238:
            if (((uVar2 & 0xffff) == 0) && (iVar3 = (int)lVar12, uVar1 != 0)) {
              if (param_5 != (int *)0x0) {
                *param_5 = *param_5 + 1;
              }
              if (local_78 == 0) break;
            }
            else {
              uVar1 = 0xfffffdfe;
              if ((uVar2 & 0xffff) != 0xfffe) {
                uVar1 = uVar2;
              }
              if (*param_4 <= iVar4 + 2) {
                uVar6 = FUN_710225e120((long)(iVar4 + 1));
                thunk_EXT_FUN_02e95df0(uVar6,*param_3,(long)iVar4);
                FUN_710225e140(*param_3);
                lVar10 = FUN_710225e120((long)(*param_4 * 2 + 4));
                *param_3 = lVar10;
                thunk_EXT_FUN_02e95df0(lVar10,0,(long)(*param_4 * 2 + 4));
                *param_4 = *param_4 * 2 + 4;
                thunk_EXT_FUN_02e95df0(*param_3,uVar6,(long)iVar4);
                FUN_710225e140(uVar6);
              }
              iVar7 = iVar4;
              if (0x80 < (uVar1 >> 8 & 0xff)) {
                lVar10 = *param_3;
                iVar7 = iVar4 + 1;
                lVar12 = lVar12 + 1;
                *(undefined1 *)(lVar10 + iVar4) = (char)(uVar1 >> 8);
                ((undefined1 *)(lVar10 + iVar4))[1] = 0;
              }
              lVar10 = *param_3;
              lVar12 = lVar12 + 1;
              iVar3 = (int)lVar12;
              *(undefined1 *)(lVar10 + iVar7) = (char)uVar1;
              ((undefined1 *)(lVar10 + iVar7))[1] = 0;
              if (local_78 == 0) break;
              iVar4 = iVar7 + 1;
            }
          }
        }
        iVar3 = (int)lVar12;
        uVar8 = uVar8 + 1;
      } while (uVar8 < uVar11);
      iVar4 = 0;
      if (uVar8 != 0) {
        iVar4 = iVar3;
      }
    }
  }
  return iVar4;
}



undefined4 FUN_7100013370(uint param_1)

{
  if (*(long *)(&DAT_71037c0c68 + (ulong)(param_1 >> 8 & 0xff) * 8) != 0) {
    return *(undefined4 *)
            (*(long *)(&DAT_71037c0c68 + (ulong)(param_1 >> 8 & 0xff) * 8) +
            (ulong)(param_1 & 0xff) * 4);
  }
  return 0;
}



undefined4 FUN_71000133a0(uint param_1)

{
  if (*(long *)(&DAT_71037c1468 + (ulong)(param_1 >> 8 & 0xff) * 8) != 0) {
    return *(undefined4 *)
            (*(long *)(&DAT_71037c1468 + (ulong)(param_1 >> 8 & 0xff) * 8) +
            (ulong)(param_1 & 0xff) * 4);
  }
  return 0;
}



undefined8 FUN_71000133d0(uint param_1,long *param_2,ulong *param_3)

{
  byte bVar1;
  byte bVar2;
  long lVar3;
  byte *pbVar4;
  
  if (param_1 == 0xffff) {
    return 1;
  }
  if (param_1 < 0x80) {
    lVar3 = 1;
    if (*param_3 == 0) {
      return 0;
    }
  }
  else if (param_1 < 0x800) {
    lVar3 = 2;
    if (*param_3 < 2) {
      return 0;
    }
  }
  else if (param_1 < 0x10000) {
    lVar3 = 3;
    if (*param_3 < 3) {
      return 0;
    }
  }
  else {
    if (0x10 < param_1 >> 0x10) {
      return 0xffffffffffffffff;
    }
    lVar3 = 4;
    if (*param_3 < 4) {
      return 0;
    }
  }
  if (3 < lVar3 - 1U) goto LAB_71000134f8;
  pbVar4 = (byte *)*param_2;
  bVar2 = (byte)param_1;
  switch(lVar3) {
  case 1:
    *pbVar4 = bVar2;
    goto LAB_71000134f8;
  case 2:
    *pbVar4 = (byte)(param_1 >> 6) | 0xc0;
    pbVar4[1] = bVar2 & 0x3f | 0x80;
    goto LAB_71000134f8;
  case 3:
    *pbVar4 = (byte)(param_1 >> 0xc) | 0xe0;
    pbVar4[1] = (byte)(param_1 >> 6) & 0x3f | 0x80;
    break;
  case 4:
    bVar1 = bVar2 & 0x3f;
    *pbVar4 = (byte)(param_1 >> 0x12) | 0xf0;
    bVar2 = (byte)(param_1 >> 6);
    pbVar4[1] = (byte)(param_1 >> 0xc) & 0x3f | 0x80;
    pbVar4[3] = bVar1 | 0x80;
  }
  pbVar4[2] = bVar2 & 0x3f | 0x80;
LAB_71000134f8:
  *param_3 = *param_3 - lVar3;
  *param_2 = *param_2 + lVar3;
  return 1;
}



uint FUN_7100013520(long *param_1,ulong *param_2)

{
  byte *pbVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  bool bVar5;
  uint uVar6;
  byte *pbVar7;
  byte *pbVar8;
  uint uVar9;
  ulong uVar10;
  
  pbVar7 = (byte *)*param_1;
  pbVar8 = pbVar7 + 1;
  bVar2 = *pbVar7;
  uVar9 = (uint)bVar2;
  if (bVar2 < 0xc0) {
    if ((char)bVar2 < '\0') {
      uVar9 = 0xfffe;
    }
    *param_2 = (ulong)(pbVar7 + (*param_2 - (long)pbVar8));
    *param_1 = (long)pbVar8;
    return uVar9;
  }
  uVar6 = (uint)bVar2;
  if (uVar9 < 0xe0) {
    if (1 < *param_2) {
      uVar9 = pbVar7[1] & 0x3f | (uVar6 & 0x1f) << 6;
      pbVar1 = pbVar7 + 2;
      if ((pbVar7[1] & 0xc0) != 0x80) {
        uVar9 = 0xfffe;
        pbVar1 = pbVar8;
      }
      *param_2 = (ulong)(pbVar7 + (*param_2 - (long)pbVar1));
      *param_1 = (long)pbVar1;
      return uVar9;
    }
    return 0xffff;
  }
  if (uVar6 < 0xf0) {
    uVar10 = *param_2;
    if (uVar10 < 3) {
      return 0xffff;
    }
    if ((*pbVar8 & 0xc0) == 0x80) {
      bVar5 = (pbVar7[2] & 0xc0) == 0x80;
      pbVar1 = pbVar8;
      if (bVar5) {
        pbVar1 = pbVar7 + 3;
      }
      uVar6 = 0xfffe;
      if (bVar5) {
        uVar6 = (uVar9 & 0xf) << 0xc | (*pbVar8 & 0x3f) << 6 | pbVar7[2] & 0x3f;
      }
      *param_2 = (ulong)(pbVar7 + (uVar10 - (long)pbVar1));
      *param_1 = (long)pbVar1;
      return uVar6;
    }
  }
  else {
    uVar10 = *param_2;
    if (uVar6 < 0xf5) {
      if (uVar10 < 4) {
        return 0xffff;
      }
      bVar2 = *pbVar8;
      if (((((bVar2 & 0xf0) == 0x80 && uVar6 == 0xf4) || ((bVar2 & 0xc0) == 0x80)) &&
          (bVar3 = pbVar7[2], (bVar3 & 0xc0) == 0x80)) &&
         (bVar4 = pbVar7[3], (bVar4 & 0xc0) == 0x80)) {
        *param_2 = (ulong)(pbVar7 + (uVar10 - (long)(pbVar7 + 4)));
        *param_1 = (long)(pbVar7 + 4);
        return (uVar9 & 7) << 0x12 | (bVar2 & 0x3f) << 0xc | (bVar3 & 0x3f) << 6 | bVar4 & 0x3f;
      }
    }
  }
  *param_2 = (ulong)(pbVar7 + (uVar10 - (long)pbVar8));
  *param_1 = (long)pbVar8;
  return 0xfffe;
}



long FUN_71000136d0(undefined8 param_1,undefined2 *param_2,int param_3)

{
  long lVar1;
  undefined8 uVar2;
  
  ret_7100015990();
  lVar1 = FUN_71000159b0(0x2a8);
  if (lVar1 == 0) {
    *param_2 = 2;
    return 0;
  }
  ret_7100015990();
  *(undefined1 *)(lVar1 + 0x220) = 0;
  *(undefined8 *)(lVar1 + 0x20c) = 0x6400000064;
  *(undefined4 *)(lVar1 + 0x208) = 100;
  *(undefined4 *)(lVar1 + 0x21c) = 300;
  *(undefined8 *)(lVar1 + 0x214) = 0x32000000000;
  *(undefined8 *)(lVar1 + 0x224) = 0xffffffffffffffff;
  *(undefined8 *)(lVar1 + 0x22c) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x234) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x23c) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x244) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x24c) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x254) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x25c) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x264) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x26c) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x274) = 0x12c000000c8;
  *(undefined8 *)(lVar1 + 0x27c) = 0x12c000000c8;
  FUN_7100015a60(lVar1,param_3);
  uVar2 = FUN_71000c0250(lVar1,param_2,param_3);
  if (((uint)uVar2 >> 0xf & 1) == 0) {
    *param_2 = 0;
    *(undefined1 *)(DAT_7103a69260 + param_3) = 1;
    return lVar1;
  }
  return 0;
}



long FUN_7100013830(undefined2 *param_1,uint param_2,int param_3)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  auto_FUN_7100013fd0_param_1 *paVar4;
  undefined8 *puVar5;
  long *plVar6;
  undefined8 uVar7;
  undefined4 uVar8;
  
  ret_7100015990();
  if (DAT_7103a87268 < 0) {
LAB_710001388c:
    thunk_EXT_FUN_02e95df0(&DAT_7103a8725c);
    plVar6 = &DAT_7103e3c3e8;
    if (DAT_7103e3c3e8 == 0) {
      uVar8 = 0;
LAB_7100013938:
      *plVar6 = -0xff;
      lVar2 = FUN_71000159b0(0x3fde8);
      *plVar6 = lVar2;
      if ((lVar2 != 0) && (lVar2 != -0xff)) {
        plVar6 = (long *)(lVar2 + 0x3fda8);
        *(undefined4 *)(lVar2 + 0x34be4) = uVar8;
        *(char *)(lVar2 + 0x2cb0c) = (char)param_3;
        thunk_EXT_FUN_02e95df0(DAT_7103a69278);
        ret_7100015990();
        if ((param_2 < 8) && (DAT_7103a69288[param_2] != 0)) {
          *(long *)(lVar2 + 0x3fdb0) = DAT_7103a69288[param_2];
        }
        else if (*DAT_7103a69288 == 0) {
          *(undefined8 *)(lVar2 + 0x3fdb0) = 0;
        }
        else {
          *(long *)(lVar2 + 0x3fdb0) = *DAT_7103a69288;
        }
        ret_7100015990();
        *(undefined8 *)(lVar2 + 8) = 0;
        *(undefined2 *)(lVar2 + 0x3ceb4) = 1;
        *(undefined8 *)(lVar2 + 0x2cb10) = 0;
        *(undefined2 *)(lVar2 + 0x2cb18) = 0;
        *(undefined8 *)(lVar2 + 0x3fdb8) = 0xffffffffffffffff;
        *(undefined4 *)(lVar2 + 0x3fdc0) = 0xffffffff;
        *(undefined2 *)(lVar2 + 0x38) = 4;
        *(undefined8 *)(lVar2 + 0x3fdc4) = 0xffffffff;
        *(undefined4 *)(lVar2 + 0x3caa4) = 0xffffffff;
        *(undefined4 *)(lVar2 + 0x2cb48) = 0xffffffff;
        *(undefined8 *)(lVar2 + 0x2cb30) = 0;
        *(undefined4 *)(lVar2 + 0x3caa0) = 0xffffffff;
        *(undefined1 *)(lVar2 + 0x3fde2) = 0xff;
        *(undefined4 *)(lVar2 + 0x1a0) = 0;
        *(undefined1 *)(lVar2 + 0x212) = 0;
        *(undefined2 *)(lVar2 + 0x3a430) = 0;
        *(undefined4 *)(lVar2 + 0x1b8) = 0;
        *(undefined2 *)(lVar2 + 0x3fde0) = 0;
        *(undefined8 *)(lVar2 + 0x50) = 0;
        *(undefined8 *)(lVar2 + 0x3fdcc) = 0;
        *(undefined2 *)(lVar2 + 0x3fdd4) = 0;
        *(undefined8 *)(lVar2 + 0x2cb20) = 0;
        *(undefined8 *)(lVar2 + 0x2cb28) = 0;
        *(long *)(lVar2 + 0x218) = lVar2 + 0x220;
        *(undefined8 *)(lVar2 + 0x1a8) = 0;
        *(undefined8 *)(lVar2 + 0x1b0) = 0;
        FUN_7100018d10(lVar2 + 0x3c9e0);
        FUN_7100018d10(lVar2 + 0x3c9f8);
        FUN_7100018d10(lVar2 + 0x3ca10);
        FUN_7100018d10(lVar2 + 0x3ca28);
        FUN_7100018d10(lVar2 + 0x3ca40);
        FUN_7100018d10(lVar2 + 0x3ca58);
        FUN_7100018d10(lVar2 + 0x3ca70);
        FUN_7100018d10(lVar2 + 0x3ca88);
        FUN_7100018d80(lVar2);
        ret_7100015990();
        lVar3 = FUN_71000cb8d0();
        *plVar6 = lVar3;
        if ((&DAT_7103e3c4cd)[*(char *)(lVar2 + 0x2cb0c)] == '\0') {
          uVar7 = 0;
        }
        else {
          uVar7 = *(undefined8 *)(lVar2 + 0x3fdb0);
        }
        *(undefined8 *)(*(long *)(lVar3 + 0xbc0) + 0xc2330) = uVar7;
        plVar1 = DAT_7103a69250;
        FUN_71000cb940(*plVar6,*(undefined4 *)(*DAT_7103a69250 + 0x200));
        FUN_71000cb950(*plVar6,*(undefined4 *)(*plVar1 + 0x204));
        FUN_71000cb960(*plVar6,*(undefined4 *)(*plVar1 + 0x208));
        FUN_71000cb970(*plVar6,*(undefined4 *)(*plVar1 + 0x20c));
        ret_7100015990();
        *(undefined8 *)(lVar2 + 0x2cb00) = 0;
        *(undefined4 *)(lVar2 + 0x2cb08) = 0;
        paVar4 = (auto_FUN_7100013fd0_param_1 *)FUN_7100013ec0();
        *(auto_FUN_7100013fd0_param_1 **)(lVar2 + 0x2caf8) = paVar4;
        if (paVar4 != (auto_FUN_7100013fd0_param_1 *)0x0) {
          FUN_7100013fd0(paVar4);
          ret_7100015990();
          puVar5 = FUN_71000c1970(*(long *)(*(long *)(&DAT_7103e3c0c8 + (long)param_3 * 8) + 0x2a0))
          ;
          *(undefined8 **)(lVar2 + 0x3fdd8) = puVar5;
          if (puVar5 != (undefined8 *)0x0) {
            ret_7100015990();
            lVar3 = FUN_71000159b0(0x18);
            *(long *)(lVar2 + 0x1c0) = lVar3;
            if (lVar3 != 0) {
              uVar7 = FUN_71000159b0(12000);
              *(undefined8 *)(*(long *)(lVar2 + 0x1c0) + 8) = uVar7;
              if (*(long *)(*(long *)(lVar2 + 0x1c0) + 8) != 0) {
                lVar3 = FUN_71000159b0(0x18);
                *(long *)(lVar2 + 0x1c8) = lVar3;
                if (lVar3 != 0) {
                  uVar7 = FUN_71000159b0(12000);
                  *(undefined8 *)(*(long *)(lVar2 + 0x1c8) + 8) = uVar7;
                  if (*(long *)(*(long *)(lVar2 + 0x1c8) + 8) != 0) {
                    lVar3 = FUN_71000159b0(0x18);
                    *(long *)(lVar2 + 0x1d0) = lVar3;
                    if (lVar3 != 0) {
                      uVar7 = FUN_71000159b0(12000);
                      *(undefined8 *)(*(long *)(lVar2 + 0x1d0) + 8) = uVar7;
                      if (*(long *)(*(long *)(lVar2 + 0x1d0) + 8) != 0) {
                        lVar3 = FUN_71000159b0(0x18);
                        *(long *)(lVar2 + 0x1d8) = lVar3;
                        if (lVar3 != 0) {
                          uVar7 = FUN_71000159b0(12000);
                          *(undefined8 *)(*(long *)(lVar2 + 0x1d8) + 8) = uVar7;
                          if (*(long *)(*(long *)(lVar2 + 0x1d8) + 8) != 0) {
                            lVar3 = FUN_71000159b0(0x18);
                            *(long *)(lVar2 + 0x1e0) = lVar3;
                            if (lVar3 != 0) {
                              uVar7 = FUN_71000159b0(12000);
                              *(undefined8 *)(*(long *)(lVar2 + 0x1e0) + 8) = uVar7;
                              if (*(long *)(*(long *)(lVar2 + 0x1e0) + 8) != 0) {
                                lVar3 = FUN_71000159b0(0x18);
                                *(long *)(lVar2 + 0x1e8) = lVar3;
                                if (lVar3 != 0) {
                                  uVar7 = FUN_71000159b0(12000);
                                  *(undefined8 *)(*(long *)(lVar2 + 0x1e8) + 8) = uVar7;
                                  if (*(long *)(*(long *)(lVar2 + 0x1e8) + 8) != 0) {
                                    lVar3 = FUN_71000159b0(0x18);
                                    *(long *)(lVar2 + 0x1f0) = lVar3;
                                    if (lVar3 != 0) {
                                      uVar7 = FUN_71000159b0(12000);
                                      *(undefined8 *)(*(long *)(lVar2 + 0x1f0) + 8) = uVar7;
                                      if (*(long *)(*(long *)(lVar2 + 0x1f0) + 8) != 0) {
                                        lVar3 = FUN_71000159b0(0x18);
                                        *(long *)(lVar2 + 0x1f8) = lVar3;
                                        if (lVar3 != 0) {
                                          uVar7 = FUN_71000159b0(12000);
                                          *(undefined8 *)(*(long *)(lVar2 + 0x1f8) + 8) = uVar7;
                                          if (*(long *)(*(long *)(lVar2 + 0x1f8) + 8) != 0) {
                                            lVar3 = FUN_71000159b0(0x18);
                                            *(long *)(lVar2 + 0x200) = lVar3;
                                            if (lVar3 != 0) {
                                              uVar7 = FUN_71000159b0(12000);
                                              *(undefined8 *)(*(long *)(lVar2 + 0x200) + 8) = uVar7;
                                              if (*(long *)(*(long *)(lVar2 + 0x200) + 8) != 0) {
                                                lVar3 = FUN_71000159b0(0x18);
                                                *(long *)(lVar2 + 0x208) = lVar3;
                                                if (lVar3 != 0) {
                                                  uVar7 = FUN_71000159b0(12000);
                                                  *(undefined8 *)(*(long *)(lVar2 + 0x208) + 8) =
                                                       uVar7;
                                                  if (*(long *)(*(long *)(lVar2 + 0x208) + 8) != 0)
                                                  {
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x1c0) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x1c8);
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x1c8) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x1d0);
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x1d0) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x1d8);
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x1d8) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x1e0);
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x1e0) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x1e8);
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x1e8) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x1f0);
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x1f0) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x1f8);
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x1f8) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x200);
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x200) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x208);
                                                    *(undefined8 *)(*(long *)(lVar2 + 0x208) + 0x10)
                                                         = *(undefined8 *)(lVar2 + 0x1c0);
                                                    **(undefined1 **)(lVar2 + 0x1c0) = 0;
                                                    **(undefined1 **)(lVar2 + 0x1c8) = 1;
                                                    **(undefined1 **)(lVar2 + 0x1d0) = 2;
                                                    **(undefined1 **)(lVar2 + 0x1d8) = 3;
                                                    **(undefined1 **)(lVar2 + 0x1e0) = 4;
                                                    **(undefined1 **)(lVar2 + 0x1e8) = 5;
                                                    **(undefined1 **)(lVar2 + 0x1f0) = 6;
                                                    **(undefined1 **)(lVar2 + 0x1f8) = 7;
                                                    **(undefined1 **)(lVar2 + 0x200) = 8;
                                                    **(undefined1 **)(lVar2 + 0x208) = 9;
                                                    uVar7 = FUN_71000159b0(240000);
                                                    *(undefined8 *)(lVar2 + 0x1b0) = uVar7;
                                                    ret_7100015990();
                                                    *param_1 = 1;
                                                    ret_7100015990();
                                                    return lVar2;
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        goto LAB_7100013e90;
      }
    }
    else {
      plVar6 = &DAT_7103e3c3f0;
      if (DAT_7103e3c3f0 == 0) {
        uVar8 = 1;
        goto LAB_7100013938;
      }
      plVar6 = &DAT_7103e3c3f8;
      if (DAT_7103e3c3f8 == 0) {
        uVar8 = 2;
        goto LAB_7100013938;
      }
      plVar6 = &DAT_7103e3c400;
      if (DAT_7103e3c400 == 0) {
        uVar8 = 3;
        goto LAB_7100013938;
      }
      plVar6 = &DAT_7103e3c408;
      if (DAT_7103e3c408 == 0) {
        uVar8 = 4;
        goto LAB_7100013938;
      }
      plVar6 = &DAT_7103e3c410;
      if (DAT_7103e3c410 == 0) {
        uVar8 = 5;
        goto LAB_7100013938;
      }
      plVar6 = &DAT_7103e3c418;
      if (DAT_7103e3c418 == 0) {
        uVar8 = 6;
        goto LAB_7100013938;
      }
      plVar6 = &DAT_7103e3c420;
      if (DAT_7103e3c420 == 0) {
        uVar8 = 7;
        goto LAB_7100013938;
      }
    }
    *param_1 = 0;
    thunk_EXT_FUN_02e95df0(&DAT_7103a8725c);
  }
  else {
    if (DAT_7103e3c8d0 < DAT_7103a87268) {
      DAT_7103e3c8d0 = DAT_7103e3c8d0 + 1;
      goto LAB_710001388c;
    }
LAB_7100013e90:
    *param_1 = 0;
  }
  return 0;
}



long * FUN_7100013ec0(void)

{
  auto_FUN_7100013fd0_param_1 *paVar1;
  long lVar2;
  undefined8 uVar3;
  long lVar4;
  int iVar5;
  long lVar6;
  
  paVar1 = (auto_FUN_7100013fd0_param_1 *)FUN_71000159b0(0x40);
  if (paVar1 != (auto_FUN_7100013fd0_param_1 *)0x0) {
    *(undefined8 *)((long)&paVar1->field_0x1_w + 7) = 0x3d00000384;
    lVar2 = FUN_71000159b0(0xa8c0);
    *(long *)paVar1 = lVar2;
    if (lVar2 == 0) {
LAB_7100013fb0:
      branch_71000159D0_0x710225e140(paVar1);
      return (long *)0x0;
    }
    if (0 < *(int *)((long)&paVar1->field_0x1_w + 7)) {
      lVar2 = 0;
      lVar6 = 8;
      do {
        uVar3 = FUN_71000159b0(*(int *)((long)&paVar1[1].field_0x1_w + 2) << 3);
        *(undefined8 *)(*(long *)paVar1 + lVar6) = uVar3;
        lVar4 = *(long *)paVar1;
        if (*(long *)(lVar4 + lVar6) == 0) {
          iVar5 = *(int *)((long)&paVar1->field_0x1_w + 7);
          if (0 < iVar5) {
            lVar2 = 0;
            lVar6 = 8;
            do {
              if (*(long *)(*(long *)paVar1 + lVar6) != 0) {
                branch_71000159D0_0x710225e140(*(long *)(*(long *)paVar1 + lVar6));
                iVar5 = *(int *)((long)&paVar1->field_0x1_w + 7);
              }
              lVar2 = lVar2 + 1;
              lVar6 = lVar6 + 0x30;
            } while (lVar2 < iVar5);
            lVar4 = *(long *)paVar1;
          }
          branch_71000159D0_0x710225e140(lVar4);
          goto LAB_7100013fb0;
        }
        lVar2 = lVar2 + 1;
        lVar6 = lVar6 + 0x30;
      } while (lVar2 < *(int *)((long)&paVar1->field_0x1_w + 7));
    }
    FUN_7100013fd0(paVar1);
  }
  return (long *)paVar1;
}



void FUN_7100013fd0(auto_FUN_7100013fd0_param_1 *param_1)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  
  if (param_1 != (auto_FUN_7100013fd0_param_1 *)0x0) {
    lVar1 = 0;
    *(undefined4 *)((long)&param_1[1].field_0x1_w + 6) = 0;
    *(undefined8 *)((long)&param_1->field_0x1_w + 7) = 0x3d00000384;
    do {
      lVar2 = lVar1 * 0x30;
      *(undefined2 *)(*(long *)param_1 + lVar2) = 0;
      *(undefined4 *)(*(long *)param_1 + lVar2 + 0x10) = 0;
      *(undefined4 *)(*(long *)param_1 + lVar2 + 0x14) = 0;
      *(undefined4 *)(*(long *)param_1 + lVar2 + 0x18) = 0;
      *(undefined4 *)(*(long *)param_1 + lVar2 + 0x1c) = 0;
      *(undefined4 *)(*(long *)param_1 + lVar2 + 0x20) = 0;
      *(undefined4 *)(*(long *)param_1 + lVar2 + 0x24) = 0;
      *(undefined4 *)(*(long *)param_1 + lVar2 + 0x28) = 0;
      if (0 < *(int *)((long)&param_1[1].field_0x1_w + 2)) {
        lVar3 = 0;
        lVar4 = 0;
        do {
          lVar4 = lVar4 + 1;
          *(undefined2 *)(*(long *)(*(long *)param_1 + lVar2 + 8) + lVar3 + 4) = 0;
          *(undefined4 *)(*(long *)(*(long *)param_1 + lVar2 + 8) + lVar3) = 0;
          lVar3 = lVar3 + 8;
        } while (lVar4 < *(int *)((long)&param_1[1].field_0x1_w + 2));
      }
      lVar1 = lVar1 + 1;
    } while (lVar1 < *(int *)((long)&param_1->field_0x1_w + 7));
    *(undefined8 *)((long)&param_1[2].field_0x1_w + 1) = 0xffffffff;
    param_1[3].field_0x1_w = 0xffffffff;
    *(undefined8 *)(param_1 + 4) = 0xffffffffffffffff;
    *(undefined8 *)((long)&param_1[4].field_0x1_w + 7) = 0xffffffff00000000;
    *(undefined8 *)((long)&param_1[5].field_0x1_w + 6) = 0xffffffff00000000;
  }
  return;
}



undefined8
FUN_71000140e0(long param_1,auto_FUN_71000140e0_param_2 *param_2,ulong param_3,uint *param_4,
              uint *param_5,uint *param_6)

{
  undefined1 *puVar1;
  char cVar2;
  byte bVar3;
  ulong uVar4;
  int *piVar5;
  int iVar6;
  
  *(undefined2 *)&param_2->field_0x210 = 0;
  *(undefined2 *)(*(long *)&param_2->field_0x218 + 0x2c890) = 0;
  *(undefined2 *)(*(long *)&param_2->field_0x218 + 0x2c892) = 0;
  puVar1 = &param_2[2].field_0xcc18;
  *(undefined8 *)&param_2[2].field_0xcc5c = 0;
  do {
    FUN_71000cc090(param_1,(auto_FUN_71000cc090_param_2 *)param_2,param_3,param_4,param_5,param_6);
    if (*(int *)((long)&param_2->field_0x1_r + 3) < 0) {
      return 0;
    }
    if (param_2->field_0x212 != '\0') {
      return 0;
    }
    cVar2 = param_2->field_0x38;
  } while (cVar2 == '\0');
  if (param_2->field_0x39 == '\x01') {
    FUN_71000a8d20(param_1,(long)param_2);
    cVar2 = param_2->field_0x38;
  }
  if (cVar2 == '\x01') {
    return 0;
  }
  uVar4 = FUN_71000cd770(param_1,(long)param_2);
  if (((uVar4 & 0xffff) == 0) || (uVar4 = FUN_71000a86a0((long)param_2), (uVar4 & 0xffff) == 0)) {
    return 0xffff;
  }
  piVar5 = *(int **)(*(long *)&param_2->field_0x218 + 0x2c898);
  iVar6 = *piVar5;
  if (iVar6 < 0) {
    iVar6 = *(int *)&param_2[3].field_0xff48;
    if (iVar6 < 0) {
      iVar6 = *(int *)&param_2[3].field_0xff44;
      if (-1 < iVar6) goto LAB_7100014210;
      if (((param_2[3].field_0xd040 != '\0') || (*(int *)puVar1 != 0)) ||
         (param_2[2].field_0xcc20 != '\0')) goto LAB_7100014248;
      if (param_2[3].field_0xff6d != '\0') goto LAB_7100014228;
      iVar6 = *(int *)(param_1 + 0x218);
    }
    else {
      if (param_2[3].field_0xd040 == '\0') {
LAB_7100014210:
        if ((*(int *)puVar1 == 0) && (param_2[2].field_0xcc20 == '\0')) {
          if (param_2[3].field_0xff6d != '\0') {
LAB_7100014228:
            iVar6 = *(int *)(param_1 + 0x21c);
          }
          goto LAB_710001424c;
        }
      }
LAB_7100014248:
      iVar6 = 0;
    }
LAB_710001424c:
    *piVar5 = iVar6;
    piVar5 = *(int **)(*(long *)&param_2->field_0x218 + 0x2c898);
    iVar6 = *piVar5;
  }
  if (0xfffe < iVar6) {
    *piVar5 = 0xffff;
  }
  *(undefined4 *)puVar1 = *(undefined4 *)&param_2[2].field_0xcc1c;
  param_2[3].field_0xff6d = param_2[3].field_0xff6c;
  param_2[2].field_0xcc20 = param_2[2].field_0xcc21;
  bVar3 = param_2->field_0x39;
  if (bVar3 - 3 < 2) {
    FUN_71000a8e80(param_1,(long)param_2);
    bVar3 = param_2->field_0x39;
    if (bVar3 != 5) goto joined_r0x0071000142e4;
  }
  else if (bVar3 != 5) goto joined_r0x0071000142e4;
  FUN_71000a92e0(param_1,(long)param_2);
  bVar3 = param_2->field_0x39;
joined_r0x0071000142e4:
  if ((bVar3 & 0xfe) != 6) {
    return 0;
  }
  FUN_71000a94b0(param_1,(long)param_2);
  return 0;
}



undefined8
FUN_7100014320(long param_1,auto_FUN_7100014320_param_2 *param_2,ulong param_3,uint *param_4,
              uint *param_5,uint *param_6)

{
  long *plVar1;
  undefined8 uVar2;
  short *psVar3;
  
  plVar1 = DAT_7103a69250;
  FUN_71000cb970(*(long *)&param_2[5].field_0x7f66,*(undefined4 *)(*DAT_7103a69250 + 0x20c));
  FUN_71000cb950(*(long *)&param_2[5].field_0x7f66,*(undefined4 *)(*plVar1 + 0x204));
  FUN_71000cb960(*(long *)&param_2[5].field_0x7f66,*(undefined4 *)(*plVar1 + 0x208));
  *(undefined4 *)&param_2->field_0x1a0 = 0;
  if (param_2->field_0x212 != '\0') {
    return 0;
  }
  do {
    FUN_71000de7a0(param_1,(long)param_2);
    if (*(short *)&param_2->field_0x210 == 1) {
      return 0;
    }
    if ((*(int *)&param_2[3].field_0xb2c2 <= *(int *)&param_2[3].field_0xb2c6) &&
       (*(short *)&param_2->field_0x210 == 0)) {
      *(short *)(*(long *)&param_2->field_0x218 + 0x2c890) =
           *(short *)(*(long *)&param_2->field_0x218 + 0x2c890) + 1;
      *(undefined2 *)(*(long *)&param_2->field_0x218 + 0x2c892) = 0;
      *(undefined8 *)&param_2[3].field_0xb2c6 = 0;
      psVar3 = *(short **)&param_2->field_0x218;
      if ((psVar3[1] == 0) || (psVar3[0x16448] == *psVar3)) {
        uVar2 = FUN_71000140e0(param_1,(auto_FUN_71000140e0_param_2 *)param_2,param_3,param_4,
                               param_5,param_6);
        while ((((uint)uVar2 >> 0xf & 1) != 0 ||
               (*(short *)(*(long *)&param_2->field_0x218 + 2) == 0))) {
          uVar2 = FUN_71000140e0(param_1,(auto_FUN_71000140e0_param_2 *)param_2,param_3,param_4,
                                 param_5,param_6);
          if (param_2->field_0x212 != '\0') {
            return uVar2;
          }
        }
      }
    }
  } while (param_2->field_0x212 == '\0');
  return 0;
}



int FUN_7100014480(long param_1,auto_FUN_7100014480_param_2 *param_2,ulong param_3,uint *param_4,
                  uint *param_5,uint *param_6)

{
  bool bVar1;
  undefined1 *puVar2;
  undefined1 *puVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  long lVar7;
  short *psVar8;
  long lVar9;
  short *psVar10;
  long lVar11;
  uint uVar12;
  
  *(ulong *)&param_2[3].field_0x64 = param_3;
  FUN_7100014320(param_1,(auto_FUN_7100014320_param_2 *)param_2,param_3,param_4,param_5,param_6);
  iVar5 = *(int *)(param_1 + 0x214);
  if (iVar5 != 0) {
    uVar12 = *(uint *)&param_2[3].field_0x5c;
    puVar2 = &param_2[0x906].field_0x40;
    psVar8 = *(short **)&param_2[3].field_0x64;
    puVar3 = &param_2[0x8a1].field_0x44;
    uVar4 = uVar12;
    if ((int)uVar12 < 0) {
      uVar4 = uVar12 + 1;
    }
    uVar4 = (int)uVar4 >> 1;
    if (iVar5 < 1) {
      if (1 < (int)uVar12) {
        lVar11 = (ulong)(uVar4 - 1) << 1;
        uVar12 = uVar4;
        do {
          if (lVar11 == 0) {
            iVar5 = (*(int *)(param_1 + 0x214) * (int)*(short *)puVar3 + 0x32) / 100 + (int)*psVar8;
            if (iVar5 < -0x7ffe) {
              iVar5 = -0x7fff;
            }
            if (0x7ffd < iVar5) {
              iVar5 = 0x7ffe;
            }
            *(short *)puVar2 = (short)iVar5;
            break;
          }
          iVar5 = (*(int *)(param_1 + 0x214) * (int)((short *)((long)psVar8 + lVar11))[-1] + 0x32) /
                  100 + (int)*(short *)((long)psVar8 + lVar11);
          if (iVar5 < -0x7ffe) {
            iVar5 = -0x7fff;
          }
          if (0x7ffd < iVar5) {
            iVar5 = 0x7ffe;
          }
          uVar6 = uVar12 - 1;
          *(short *)(puVar2 + lVar11) = (short)iVar5;
          lVar11 = lVar11 + -2;
          bVar1 = 0 < (int)uVar12;
          uVar12 = uVar6;
        } while (uVar6 != 0 && bVar1);
      }
      psVar10 = psVar8 + (int)(uVar4 - 1);
    }
    else if ((int)uVar12 < 2) {
      psVar10 = (short *)&param_2[0x906].field_0x3e;
    }
    else {
      iVar5 = (iVar5 * *(short *)puVar3 + 0x32) / 100 + (int)*psVar8;
      if (iVar5 < -0x7ffe) {
        iVar5 = -0x7fff;
      }
      if (0x7ffd < iVar5) {
        iVar5 = 0x7ffe;
      }
      *(short *)puVar2 = (short)iVar5;
      if ((uVar12 & 0xfffffffe) == 2) {
        lVar11 = 0;
      }
      else {
        uVar12 = (uint)*(ushort *)puVar2;
        lVar11 = 0;
        do {
          lVar9 = lVar11 * 2;
          lVar7 = lVar11 + 1;
          lVar11 = lVar11 + 1;
          uVar12 = (*(int *)(param_1 + 0x214) * (int)(short)uVar12 + 0x32) / 100 +
                   (int)psVar8[lVar7];
          if ((int)uVar12 < -0x7ffe) {
            uVar12 = 0xffff8001;
          }
          if (0x7ffd < (int)uVar12) {
            uVar12 = 0x7ffe;
          }
          *(short *)(&param_2[0x906].field_0x42 + lVar9) = (short)uVar12;
        } while ((ulong)uVar4 - 1 != lVar11);
      }
      psVar10 = (short *)(puVar2 + (long)(int)lVar11 * 2);
    }
    *(short *)puVar3 = *psVar10;
    thunk_EXT_FUN_02e95df0(psVar8,puVar2,(long)(int)(uVar4 << 1));
  }
  return *(int *)&param_2[3].field_0x5c;
}



undefined8
FUN_7100014690(long param_1,auto_FUN_7100014690_param_2 *param_2,ulong param_3,uint *param_4,
              uint *param_5,uint *param_6)

{
  undefined4 uVar1;
  undefined8 uVar2;
  
  *(undefined4 *)((long)&param_2->field_0x1_w + 3) = 0;
  *(ulong *)((long)&param_2[1].field_0x1_w + 2) = param_3;
  uVar1 = thunk_EXT_FUN_02e95df0(param_3);
  *(undefined4 *)param_2 = uVar1;
  *(undefined1 *)(param_2 + 0x6a) = 0;
  do {
    uVar2 = FUN_71000140e0(param_1,(auto_FUN_71000140e0_param_2 *)param_2,param_3,param_4,param_5,
                           param_6);
    if (*(char *)(param_2 + 0x6a) != '\0') {
      return 0xffff;
    }
  } while ((((uint)uVar2 >> 0xf & 1) != 0) ||
          (*(short *)(*(long *)&param_2[0x6b].field_0x1_w + 2) == 0));
  return 0;
}



undefined8 FUN_7100014710(long param_1)

{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  int iVar4;
  long *plVar5;
  long lVar6;
  
  uVar3 = 0;
  if (param_1 != 0) {
    ret_71000159A0();
    thunk_EXT_FUN_02e95df0(DAT_7103a69278);
    iVar1 = *(int *)(param_1 + 0x34be4);
    FUN_71000cb910(*(long *)(param_1 + 0x3fda8));
    if (*(long *)(param_1 + 8) != 0) {
      branch_71000159D0_0x710225e140(*(long *)(param_1 + 8));
    }
    if (*(long *)(param_1 + 0x2cb28) != 0) {
      branch_71000159D0_0x710225e140(*(long *)(param_1 + 0x2cb28));
    }
    if (*(long *)(param_1 + 0x2cb30) != 0) {
      branch_71000159D0_0x710225e140(*(long *)(param_1 + 0x2cb30));
    }
    if (*(long *)(param_1 + 0x2cb20) != 0) {
      branch_71000159D0_0x710225e140(*(long *)(param_1 + 0x2cb20));
    }
    FUN_7100018d30(param_1 + 0x3c9e0);
    FUN_7100018d30(param_1 + 0x3c9f8);
    FUN_7100018d30(param_1 + 0x3ca10);
    FUN_7100018d30(param_1 + 0x3ca28);
    FUN_7100018d30(param_1 + 0x3ca40);
    FUN_7100018d30(param_1 + 0x3ca58);
    FUN_7100018d30(param_1 + 0x3ca70);
    FUN_7100018d30(param_1 + 0x3ca88);
    FUN_7100018dd0(param_1);
    plVar5 = *(long **)(param_1 + 0x2caf8);
    if (plVar5 != (long *)0x0) {
      lVar2 = *plVar5;
      if (lVar2 != 0) {
        iVar4 = (int)plVar5[1];
        if (0 < iVar4) {
          lVar2 = 0;
          lVar6 = 8;
          do {
            if (*(long *)(*plVar5 + lVar6) != 0) {
              branch_71000159D0_0x710225e140(*(long *)(*plVar5 + lVar6));
              iVar4 = (int)plVar5[1];
            }
            lVar2 = lVar2 + 1;
            lVar6 = lVar6 + 0x30;
          } while (lVar2 < iVar4);
          lVar2 = *plVar5;
        }
        branch_71000159D0_0x710225e140(lVar2);
      }
      branch_71000159D0_0x710225e140(plVar5);
    }
    FUN_71000c1bb0(*(auto_FUN_71000c1bb0_param_1 **)(param_1 + 0x3fdd8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x1b0));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x1c0) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x1c0));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x1c8) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x1c8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x1d0) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x1d0));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x1d8) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x1d8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x1e0) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x1e0));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x1e8) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x1e8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x1f0) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x1f0));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x1f8) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x1f8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x200) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x200));
    branch_71000159D0_0x710225e140(*(undefined8 *)(*(long *)(param_1 + 0x208) + 8));
    branch_71000159D0_0x710225e140(*(undefined8 *)(param_1 + 0x208));
    branch_71000159D0_0x710225e140(param_1);
    *(undefined8 *)(DAT_7103a69280 + (long)iVar1 * 8) = 0;
    thunk_EXT_FUN_02e95df0(DAT_7103a69278);
    uVar3 = 1;
  }
  return uVar3;
}



undefined8 FUN_7100014980(uint param_1,char *param_2,short *param_3,uint param_4)

{
  uint *puVar1;
  undefined8 uVar2;
  ulong uVar3;
  long lVar4;
  
  if (7 < param_1) {
    return 0xffff;
  }
  if (DAT_7103e3c0b8 == '\0') {
    return 0xfffd;
  }
  if (param_3 == (short *)0x0) {
    return 0xfffd;
  }
  if ((int)param_4 < 1) {
    return 0xfffd;
  }
  uVar3 = (ulong)param_1;
  thunk_EXT_FUN_02e95df0(&DAT_7103a8725c);
  if (*(long *)(&DAT_7103e3c428 + uVar3 * 8) == 0) {
    lVar4 = uVar3 * 8;
    *(undefined8 *)(&DAT_7103e3c428 + lVar4) = 0xffffffffffffff01;
    uVar2 = DAT_7103a69278;
    thunk_EXT_FUN_02e95df0(DAT_7103a69278);
    puVar1 = FUN_710009d880(param_2,param_3,param_4,0);
    *(uint **)(&DAT_7103e3c428 + lVar4) = puVar1;
    thunk_EXT_FUN_02e95df0(uVar2);
    if (*(long *)(&DAT_7103e3c428 + lVar4) != 0) {
      if (*(long *)(&DAT_7103e3c428 + lVar4) != -0xff) {
        uVar2 = 1;
        goto LAB_7100014a64;
      }
      *(undefined8 *)(&DAT_7103e3c428 + uVar3 * 8) = 0;
    }
    uVar2 = 0xfffd;
  }
  else {
    uVar2 = 0xfffe;
  }
LAB_7100014a64:
  thunk_EXT_FUN_02e95df0(&DAT_7103a8725c);
  return uVar2;
}



ushort FUN_7100014a90(uint param_1,uint param_2,char *param_3,char *param_4,long param_5,int param_6
                     )

{
  uint uVar1;
  byte bVar2;
  char cVar3;
  int *piVar4;
  byte *pbVar5;
  undefined8 *puVar6;
  long *plVar7;
  undefined8 *puVar8;
  ulong uVar9;
  undefined8 uVar10;
  long lVar11;
  undefined *puVar12;
  long lVar13;
  char *pcVar14;
  uint uVar15;
  int iVar16;
  long lVar17;
  ulong uVar18;
  long lVar19;
  long lVar20;
  undefined4 local_46c;
  undefined1 auStack_468 [512];
  undefined2 local_268;
  undefined2 uStack_266;
  undefined2 uStack_264;
  undefined2 uStack_262;
  undefined4 local_260;
  undefined2 uStack_25c;
  undefined1 auStack_25a [506];
  
  if (param_5 == 0) {
    return 0xb;
  }
  if (param_6 < 1) {
    return 0xb;
  }
  ret_7100015980();
  ret_7100015960();
  if (*DAT_7103a692a8 < 0) {
    *DAT_7103a692a8 = 0;
  }
  uVar15 = param_2;
  if (99 < param_2) {
    uVar15 = 6;
  }
  FUN_71000159e0(uVar15);
  if (*DAT_7103a68fd8 == 0) {
    ret_71000159A0();
    if (param_3 != (char *)0x0) goto LAB_7100014b48;
LAB_7100014c30:
    pbVar5 = DAT_7103a68f18;
    pbVar5[0] = 0x2e;
    pbVar5[1] = 0x2e;
    pbVar5[2] = 0x2f;
    pbVar5[3] = 0;
  }
  else {
    if (param_3 == (char *)0x0) goto LAB_7100014c30;
LAB_7100014b48:
    if (*param_3 == '\0') goto LAB_7100014c30;
    thunk_EXT_FUN_02e95df0(&local_268,param_3);
    uVar9 = thunk_EXT_FUN_02e95df0(&local_268);
    if (0 < (int)uVar9) {
      if ((uVar9 & 0xffffffff) == 1) {
        lVar17 = 0;
      }
      else {
        lVar17 = 0;
        do {
          if (*(char *)((long)&local_268 + lVar17) == '\\') {
            *(undefined1 *)((long)&local_268 + lVar17) = 0x2f;
            cVar3 = *(char *)((long)&local_268 + lVar17 + 1);
          }
          else {
            cVar3 = *(char *)((long)&local_268 + lVar17 + 1);
          }
          if (cVar3 == '\\') {
            *(undefined1 *)((long)&local_268 + lVar17 + 1) = 0x2f;
          }
          lVar17 = lVar17 + 2;
        } while ((uVar9 & 0xffffffff) - (uVar9 & 1) != lVar17);
      }
      if (((uVar9 & 1) != 0) && (*(char *)((long)&local_268 + lVar17) == '\\')) {
        *(undefined1 *)((long)&local_268 + lVar17) = 0x2f;
      }
    }
    if (((int)uVar9 < 0x1ff) &&
       (lVar17 = uVar9 << 0x20, *(char *)((long)&local_268 + (lVar17 + -0x100000000 >> 0x20)) != '/'
       )) {
      *(undefined1 *)((long)&local_268 + (lVar17 >> 0x20)) = 0x2f;
      *(undefined1 *)((long)&local_268 + (lVar17 + 0x100000000 >> 0x20)) = 0;
    }
    if (*DAT_7103a692a0 != '\x01') {
LAB_7100014c58:
      thunk_EXT_FUN_02e95df0(DAT_7103a68f18,&local_268);
      pbVar5 = DAT_7103a68f18;
      uVar9 = thunk_EXT_FUN_02e95df0(DAT_7103a68f18);
      iVar16 = (int)uVar9;
      goto joined_r0x007100014c50;
    }
    iVar16 = FUN_7100016400(DAT_7103a68f18,(byte *)&local_268);
    if (iVar16 != 0) {
      if (*(char *)((long)DAT_7103a69260 + (long)(int)param_2) == '\x01') {
        return 1;
      }
      goto LAB_7100014c58;
    }
  }
  pbVar5 = DAT_7103a68f18;
  uVar9 = thunk_EXT_FUN_02e95df0(DAT_7103a68f18);
  iVar16 = (int)uVar9;
joined_r0x007100014c50:
  if (0 < iVar16) {
    if ((uVar9 & 0xffffffff) == 1) {
      lVar17 = 0;
    }
    else {
      lVar17 = 0;
      do {
        if (pbVar5[lVar17] == 0x5c) {
          pbVar5[lVar17] = 0x2f;
          bVar2 = pbVar5[lVar17 + 1];
        }
        else {
          bVar2 = pbVar5[lVar17 + 1];
        }
        if (bVar2 == 0x5c) {
          pbVar5[lVar17 + 1] = 0x2f;
        }
        lVar17 = lVar17 + 2;
      } while ((uVar9 & 0xffffffff) - (uVar9 & 1) != lVar17);
    }
    if (((uVar9 & 1) != 0) && (pbVar5[lVar17] == 0x5c)) {
      pbVar5[lVar17] = 0x2f;
    }
  }
  if (((int)uVar9 < 0x1ff) &&
     (lVar17 = uVar9 << 0x20, pbVar5[lVar17 + -0x100000000 >> 0x20] != 0x2f)) {
    pbVar5[lVar17 >> 0x20] = 0x2f;
    pbVar5[lVar17 + 0x100000000 >> 0x20] = 0;
  }
  if ((param_3 == (char *)0x0) || (*param_3 == '\0')) {
    thunk_EXT_FUN_02e95df0(DAT_7103a692b0,&DAT_71030ce987,DAT_7103a68f18,"fixed_db/");
    uVar10 = FUN_7100016580(param_5);
    iVar16 = (int)uVar10;
    piVar4 = DAT_7103a69248;
    pcVar14 = DAT_7103a692a0;
  }
  else {
    pcVar14 = "tts_single_db.vtdb2";
    if (*param_4 != '\0') {
      pcVar14 = param_4;
    }
    thunk_EXT_FUN_02e95df0(auStack_468,&DAT_71030ce987,DAT_7103a68f18,pcVar14);
    thunk_EXT_FUN_02e95df0(DAT_7103a69240 + 0x200,auStack_468);
    uVar10 = FUN_7100016580(param_5);
    if ((int)uVar10 < 0) {
      return 0xb;
    }
    lVar17 = FUN_7100016090();
    piVar4 = DAT_7103a69238;
    if (lVar17 != 0) {
      FUN_7100016100((long)DAT_7103a69238,4,1,lVar17);
      FUN_7100016100((long)&local_268,4,1,lVar17);
      if (CONCAT22(uStack_266,local_268) == 0x200) {
        FUN_7100016100((long)&local_46c,4,1,lVar17);
        lVar11 = DAT_7103a69240;
        FUN_7100016100(DAT_7103a69240,1,CONCAT22(uStack_266,local_268),lVar17);
        if (0 < *piVar4) {
          uVar9 = (ulong)CONCAT22(uStack_266,local_268);
          lVar19 = 0;
          lVar13 = lVar11;
          do {
            lVar20 = lVar11 + lVar19 * 0x408;
            FUN_7100016100(lVar20,1,(uint)uVar9,lVar17);
            FUN_7100016100(lVar20 + 0x200,1,CONCAT22(uStack_266,local_268),lVar17);
            FUN_7100016100(lVar20 + 0x400,4,1,lVar17);
            FUN_7100016100(lVar20 + 0x404,4,1,lVar17);
            uVar1 = CONCAT22(uStack_266,local_268);
            uVar9 = (ulong)uVar1;
            if (0 < (int)uVar1) {
              cVar3 = (char)local_46c;
              if (uVar1 == 1) {
                uVar18 = 0;
              }
              else {
                uVar18 = 0;
                do {
                  pcVar14 = (char *)(lVar13 + uVar18);
                  uVar18 = uVar18 + 2;
                  *pcVar14 = *pcVar14 - cVar3;
                  pcVar14[0x200] = pcVar14[0x200] - cVar3;
                  pcVar14[1] = pcVar14[1] - cVar3;
                  pcVar14[0x201] = pcVar14[0x201] - cVar3;
                } while ((uVar9 & 0xfffffffe) != uVar18);
              }
              if ((local_268 & 1) != 0) {
                *(char *)(lVar20 + uVar18) = *(char *)(lVar20 + uVar18) - cVar3;
                lVar20 = lVar11 + lVar19 * 0x408 + uVar18;
                *(char *)(lVar20 + 0x200) = *(char *)(lVar20 + 0x200) - cVar3;
              }
            }
            lVar19 = lVar19 + 1;
            lVar13 = lVar13 + 0x408;
          } while (lVar19 < *piVar4);
        }
      }
      else {
        *piVar4 = 0;
      }
      FUN_71000160d0(lVar17);
    }
    FUN_7100016590();
    pbVar5 = DAT_7103a68f18;
    if (0 < *DAT_7103a69238) {
      lVar17 = 0;
      lVar19 = -DAT_7103a69240;
      lVar11 = DAT_7103a69240;
      do {
        puVar12 = FUN_71000159e0(uVar15);
        iVar16 = (int)DAT_7103a69240;
        thunk_EXT_FUN_02e95df0(auStack_25a,0,0x1f2);
        local_268 = 0x6264;
        uStack_266 = 0x625f;
        uStack_264 = 0x6975;
        uStack_262 = 0x646c;
        local_260 = 0x7461642e;
        uStack_25c = 0x65;
        lVar13 = thunk_EXT_FUN_02e95df0(lVar11,&local_268);
        if (lVar13 == 0) {
          local_260 = 0x6e6f6d;
          local_268 = 0x6164;
          uStack_266 = 0x6174;
          uStack_264 = 0x632d;
          uStack_262 = 0x6d6f;
          lVar13 = thunk_EXT_FUN_02e95df0(lVar11,&local_268);
          if (lVar13 != 0) goto LAB_71000153b4;
          thunk_EXT_FUN_02e95df0(&local_268,"data-%s",*(undefined8 *)(puVar12 + 0x10));
          lVar13 = thunk_EXT_FUN_02e95df0(lVar11,&local_268);
          if (lVar13 == 0) {
            iVar16 = 0;
          }
          else {
            iVar16 = (int)lVar19 + (int)lVar13;
          }
        }
        else {
LAB_71000153b4:
          iVar16 = (int)lVar13 - (iVar16 + (int)lVar17 * 0x408);
        }
        thunk_EXT_FUN_02e95df0(auStack_468,&DAT_71030ce987,pbVar5,lVar11 + iVar16);
        thunk_EXT_FUN_02e95df0(lVar11,auStack_468);
        pcVar14 = param_4;
        if (*param_4 == '\0') {
          pcVar14 = FUN_7100016040(lVar11 + 0x200);
        }
        thunk_EXT_FUN_02e95df0(auStack_468,&DAT_71030ce987,pbVar5,pcVar14);
        thunk_EXT_FUN_02e95df0(lVar11 + 0x200,auStack_468);
        lVar17 = lVar17 + 1;
        lVar11 = lVar11 + 0x408;
        lVar19 = lVar19 + -0x408;
      } while (lVar17 < *DAT_7103a69238);
    }
    thunk_EXT_FUN_02e95df0(DAT_7103a692b0,DAT_7103a68f18);
    uVar10 = FUN_7100016580(param_5);
    iVar16 = (int)uVar10;
    piVar4 = DAT_7103a69248;
    pcVar14 = DAT_7103a692a0;
  }
  if (iVar16 < 0) {
    DAT_7103a692a0 = pcVar14;
    DAT_7103a69248 = piVar4;
    return 0xb;
  }
  DAT_7103a69248 = piVar4;
  DAT_7103a692a0 = pcVar14;
  if (*pcVar14 != '\x01') {
    if (*piVar4 == 0) {
      FUN_7100015b40();
      *piVar4 = 1;
    }
    ret_7100015970();
    thunk_EXT_FUN_02e95df0(&local_268,&DAT_71030ce987,DAT_7103a68f18,"db_build.date");
    lVar17 = FUN_7100015b50((char *)&local_268,"rb");
    if (lVar17 != 0) {
      uVar1 = *(uint *)(lVar17 + 0x14);
      if (0x3fe < (int)uVar1) {
        uVar1 = 0x3ff;
      }
      FUN_7100015ef0(lVar17,0,0,0x7103e3cad4,1,uVar1);
      FUN_7100015ed0(lVar17);
      (&DAT_7103e3cad4)[(int)uVar1] = 0;
    }
    puVar6 = DAT_7103a69288;
    *DAT_7103a69288 = 0;
    puVar6[1] = 0;
    puVar6[2] = 0;
    puVar6[3] = 0;
    puVar6[4] = 0;
    puVar6[5] = 0;
    puVar6[6] = 0;
    puVar6[7] = 0;
    ret_7100015990();
    lVar17 = FUN_71000159b0(0x220);
    plVar7 = DAT_7103a69250;
    *DAT_7103a69250 = lVar17;
    if (lVar17 == 0) {
      *plVar7 = 0;
      return 2;
    }
    *(undefined1 *)(lVar17 + 0x210) = 1;
    *(undefined8 *)(lVar17 + 0x200) = 0x200000001;
    *(undefined8 *)(lVar17 + 0x208) = 0xffffffff00000003;
    ret_7100015990();
    FUN_7100015a40(*plVar7,0);
    uVar10 = FUN_71000bfff0(*plVar7,&local_268);
    if (((uint)uVar10 >> 0xf & 1) == 0) {
      local_268 = 0;
      *DAT_7103a69258 = 1;
    }
    else if (local_268 != 0) {
      if (*plVar7 != 0) {
        branch_71000159D0_0x710225e140(*plVar7);
      }
      *plVar7 = 0;
      return local_268;
    }
    *pcVar14 = '\x01';
    thunk_EXT_FUN_02e95df0(DAT_7103a69298,0,800);
    puVar6 = DAT_7103a69260;
    *DAT_7103a69260 = 0;
    puVar6[1] = 0;
    *(undefined4 *)(puVar6 + 0xc) = 0;
    puVar6[2] = 0;
    puVar6[3] = 0;
    puVar6[4] = 0;
    puVar6[5] = 0;
    puVar6[6] = 0;
    puVar6[7] = 0;
    puVar6[8] = 0;
    puVar6[9] = 0;
    puVar6[10] = 0;
    puVar6[0xb] = 0;
    puVar6 = DAT_7103a69290;
    *(undefined4 *)(DAT_7103a69290 + 0xc) = 0;
    *puVar6 = 0;
    puVar6[1] = 0;
    puVar6[2] = 0;
    puVar6[3] = 0;
    puVar6[4] = 0;
    puVar6[5] = 0;
    puVar6[6] = 0;
    puVar6[7] = 0;
    puVar6[8] = 0;
    puVar6[9] = 0;
    puVar6[10] = 0;
    puVar6[0xb] = 0;
    puVar8 = DAT_7103a69280;
    DAT_7103a69280[6] = 0;
    puVar8[7] = 0;
    puVar8[4] = 0;
    puVar8[5] = 0;
    puVar8[2] = 0;
    puVar8[3] = 0;
    puVar6 = DAT_7103a68fe0;
    *puVar8 = 0;
    puVar8[1] = 0;
    *puVar6 = 0;
    puVar6[1] = 0;
    puVar6[2] = 0;
    puVar6[3] = 0;
    puVar6[4] = 0;
    puVar6[5] = 0;
    puVar6[6] = 0;
    puVar6[7] = 0;
  }
  lVar17 = DAT_7103a69298;
  if (*(long *)(DAT_7103a69298 + (long)(int)uVar15 * 8) == 0) {
    lVar19 = (long)(int)uVar15;
    lVar11 = FUN_71000136d0((ulong)param_1,&local_268,uVar15);
    *(long *)(lVar17 + lVar19 * 8) = lVar11;
    if (local_268 != 0) {
      return local_268;
    }
    lVar13 = lVar19 * 8;
    *(long *)(lVar11 + 0x288) = *DAT_7103a69250;
    **(undefined8 **)(lVar17 + lVar13) = 0;
    puVar6 = DAT_7103a69290;
    lVar11 = *(long *)(lVar17 + lVar13);
    *(undefined1 *)((long)DAT_7103a69290 + lVar19) = 1;
    *(undefined4 *)(lVar11 + 0x298) = 1;
    *(undefined4 *)(*(long *)(lVar17 + lVar13) + 0x298) = 8;
    ret_7100015990();
    if (*(int *)(*(long *)(lVar17 + lVar13) + 0x298) - 9U < 0xfffffff8) {
      *(undefined4 *)(*(long *)(lVar17 + lVar13) + 0x298) = 1;
      *(undefined1 *)((long)puVar6 + lVar19) = 0;
    }
  }
  ret_71000159A0();
  ret_7100015970();
  ret_7100015990();
  return 0;
}



undefined * FUN_71000154b0(undefined8 param_1)

{
  uint uVar1;
  long lVar2;
  char acStack_230 [512];
  
  thunk_EXT_FUN_02e95df0(acStack_230,&DAT_71030ce987,param_1,"db_build.date");
  lVar2 = FUN_7100015b50(acStack_230,"rb");
  if (lVar2 != 0) {
    uVar1 = *(uint *)(lVar2 + 0x14);
    if (0x3fe < (int)uVar1) {
      uVar1 = 0x3ff;
    }
    FUN_7100015ef0(lVar2,0,0,0x7103e3cad4,1,uVar1);
    FUN_7100015ed0(lVar2);
    (&DAT_7103e3cad4)[(int)uVar1] = 0;
    return &DAT_7103e3cad4;
  }
  return (undefined *)0x0;
}



ushort FUN_7100015570(uint param_1,uint param_2,undefined8 param_3,long param_4,int param_5)

{
  ushort uVar1;
  
  uVar1 = FUN_7100014a90(param_1,param_2,"...","...",param_4,param_5);
  return uVar1;
}



void FUN_71000155a0(char param_1)

{
  if (DAT_7103e3c0c0 != 0) {
    *(bool *)(DAT_7103e3c0c0 + 0x210) = param_1 != '\0';
  }
  return;
}
