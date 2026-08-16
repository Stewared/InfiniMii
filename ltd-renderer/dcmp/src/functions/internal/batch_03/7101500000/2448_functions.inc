

void FUN_7101500710(undefined8 *param_1)

{
  long *plVar1;
  
  *param_1 = &DAT_71039596b8;
  if ((long *)param_1[1] != (long *)0x0) {
    (**(code **)(*(long *)param_1[1] + 0x60))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101500770. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



void FUN_7101500790(undefined8 *param_1)

{
  long *plVar1;
  long lVar2;
  
  *param_1 = &DAT_71039596d8;
  FUN_710198a210((long)param_1);
  lVar2 = param_1[4];
  if (lVar2 != 0) {
    if (DAT_7105a06420 == 0) {
      FUN_71005fbbd0(lVar2);
    }
    else {
      plVar1 = FUN_71024ef490(DAT_7105a06420,lVar2);
      if (plVar1 != (long *)0x0) {
        (**(code **)(*plVar1 + 0x38))(plVar1,lVar2);
      }
    }
  }
  param_1[5] = &DAT_7103899a28;
  if (*(char *)(param_1 + 0xc) != '\0') {
    *(undefined1 *)(param_1 + 0xc) = 0;
  }
  (**(code **)(*(long *)param_1[7] + 0x38))((long *)param_1[7],param_1[6]);
  if (*(char *)(param_1 + 0xc) != '\0') {
    *(undefined1 *)(param_1 + 0xc) = 0;
  }
  return;
}



void FUN_7101500834(undefined8 *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  
  *param_1 = &DAT_71039596d8;
  FUN_710198a210((long)param_1);
  plVar2 = DAT_7103a65db8;
  lVar3 = param_1[4];
  if (lVar3 != 0) {
    if (*DAT_7103a65db8 == 0) {
      FUN_71005fbbd0(lVar3);
    }
    else {
      plVar1 = FUN_71024ef490(*DAT_7103a65db8,lVar3);
      if (plVar1 != (long *)0x0) {
        (**(code **)(*plVar1 + 0x38))(plVar1,lVar3);
      }
    }
  }
  param_1[5] = &DAT_7103899a28;
  if (*(char *)(param_1 + 0xc) != '\0') {
    *(undefined1 *)(param_1 + 0xc) = 0;
  }
  (**(code **)(*(long *)param_1[7] + 0x38))((long *)param_1[7],param_1[6]);
  if (*plVar2 != 0) {
    plVar2 = FUN_71024ef490(*plVar2,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015008f0. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



void FUN_7101500918(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101500958. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101500bf0(void)

{
  int iVar1;
  
  if (((*DAT_7103a5ea18 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5ea18), iVar1 != 0))
  {
    *DAT_7103a5ea10 = DAT_7103a5a2f0 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5ea18);
  }
  return DAT_7103a5ea10;
}



void FUN_7101500c50(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101500c90. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long FUN_7101500ce4(void)

{
  long *plVar1;
  int iVar2;
  
  if (((*DAT_7103a5ea28 & 1) == 0) && (iVar2 = thunk_EXT_FUN_02e95df0(DAT_7103a5ea28), iVar2 != 0))
  {
    FUN_710198c140(DAT_7103a5ea20,
                   "game::util::no_rtti::TypeInfo<float *>::TypeInfo() [Type = float *]");
    thunk_EXT_FUN_02e95df0(DAT_7103a5ea28);
  }
  plVar1 = DAT_7103a5ea20;
  *(undefined1 *)((long)(int)DAT_7103a5ea20[1] + *DAT_7103a5ea20 + -1) = 0;
  return *plVar1;
}



long * FUN_7101501320(void)

{
  int iVar1;
  
  if (((*DAT_7103a5f210 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5f210), iVar1 != 0))
  {
    *DAT_7103a5f208 = DAT_7103a5a2f0 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5f210);
  }
  return DAT_7103a5f208;
}



void FUN_7101501380(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015013c0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long FUN_7101501414(void)

{
  long *plVar1;
  int iVar2;
  
  if (((*DAT_7103a5f220 & 1) == 0) && (iVar2 = thunk_EXT_FUN_02e95df0(DAT_7103a5f220), iVar2 != 0))
  {
    FUN_710198c140(DAT_7103a5f218,
                   "game::util::no_rtti::TypeInfo<sead::SafeStringBase<char> *>::TypeInfo() [Type = sead::SafeStringBase<char> *]"
                  );
    thunk_EXT_FUN_02e95df0(DAT_7103a5f220);
  }
  plVar1 = DAT_7103a5f218;
  *(undefined1 *)((long)(int)DAT_7103a5f218[1] + *DAT_7103a5f218 + -1) = 0;
  return *plVar1;
}



long * FUN_71015018c0(void)

{
  int iVar1;
  
  if (((*DAT_7103a5f230 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5f230), iVar1 != 0))
  {
    *DAT_7103a5f228 = DAT_7103a5a2f0 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5f230);
  }
  return DAT_7103a5f228;
}



void FUN_7101501920(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101501960. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long FUN_71015019b4(void)

{
  long *plVar1;
  int iVar2;
  
  if (((*DAT_7103a5f240 & 1) == 0) && (iVar2 = thunk_EXT_FUN_02e95df0(DAT_7103a5f240), iVar2 != 0))
  {
    FUN_710198c140(DAT_7103a5f238,
                   "game::util::no_rtti::TypeInfo<bool *>::TypeInfo() [Type = bool *]");
    thunk_EXT_FUN_02e95df0(DAT_7103a5f240);
  }
  plVar1 = DAT_7103a5f238;
  *(undefined1 *)((long)(int)DAT_7103a5f238[1] + *DAT_7103a5f238 + -1) = 0;
  return *plVar1;
}



long * FUN_7101501e60(void)

{
  int iVar1;
  
  if (((*DAT_7103a5f250 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5f250), iVar1 != 0))
  {
    *DAT_7103a5f248 = DAT_7103a5a2f0 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5f250);
  }
  return DAT_7103a5f248;
}



void FUN_7101501ec0(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101501f00. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long FUN_7101501f54(void)

{
  long *plVar1;
  int iVar2;
  
  if (((*DAT_7103a5f260 & 1) == 0) && (iVar2 = thunk_EXT_FUN_02e95df0(DAT_7103a5f260), iVar2 != 0))
  {
    FUN_710198c140(DAT_7103a5f258,
                   "game::util::no_rtti::TypeInfo<sead::Vector3<float> *>::TypeInfo() [Type = sead::Vector3<float> *]"
                  );
    thunk_EXT_FUN_02e95df0(DAT_7103a5f260);
  }
  plVar1 = DAT_7103a5f258;
  *(undefined1 *)((long)(int)DAT_7103a5f258[1] + *DAT_7103a5f258 + -1) = 0;
  return *plVar1;
}



long * FUN_7101502590(void)

{
  int iVar1;
  
  if (((*DAT_7103a5e9f8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5e9f8), iVar1 != 0))
  {
    *DAT_7103a5e9f0 = DAT_7103a5a2f0 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5e9f8);
  }
  return DAT_7103a5e9f0;
}



void FUN_71015025f0(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101502630. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long FUN_7101502684(void)

{
  long *plVar1;
  int iVar2;
  
  if (((*DAT_7103a5ea08 & 1) == 0) && (iVar2 = thunk_EXT_FUN_02e95df0(DAT_7103a5ea08), iVar2 != 0))
  {
    FUN_710198c140(DAT_7103a5ea00,"game::util::no_rtti::TypeInfo<int *>::TypeInfo() [Type = int *]")
    ;
    thunk_EXT_FUN_02e95df0(DAT_7103a5ea08);
  }
  plVar1 = DAT_7103a5ea00;
  *(undefined1 *)((long)(int)DAT_7103a5ea00[1] + *DAT_7103a5ea00 + -1) = 0;
  return *plVar1;
}



void FUN_71015031b8(undefined8 param_1,long param_2)

{
  long *plVar1;
  
  if (param_2 != 0) {
    if (*DAT_7103a65db8 == 0) {
      FUN_71005fbbd0(param_2);
      return;
    }
    plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_2);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015031fc. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_2);
      return;
    }
  }
  return;
}



long * FUN_710150332c(void)

{
  int iVar1;
  
  if (((*DAT_7103a618a0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a618a0), iVar1 != 0))
  {
    *DAT_7103a61898 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a618a0);
  }
  return DAT_7103a61898;
}



void FUN_710150339c(undefined8 *param_1)

{
  long *plVar1;
  
  *param_1 = &DAT_71039598f8;
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015033e8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



int FUN_7101503bc0(long *param_1,long param_2,undefined8 *param_3,undefined8 *param_4,
                  undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  long lVar2;
  undefined4 uVar3;
  ulong uVar4;
  char *pcVar5;
  long lVar6;
  char *pcVar7;
  int iVar8;
  long lVar9;
  long local_a0;
  long *local_98;
  undefined8 local_90;
  undefined1 local_88;
  long local_80;
  undefined1 **ppuStack_78;
  int local_70;
  undefined1 *local_68;
  int local_60;
  int local_54;
  char local_50 [32];
  
  lVar6 = *param_1;
  *(undefined1 *)((int)param_1[1] + lVar6 + -1) = 0;
  pcVar7 = (char *)*param_1;
  if ((pcVar7 == (char *)0x0) || (*pcVar7 == '\0')) {
LAB_7101503c24:
    lVar9 = 0;
  }
  else {
    lVar9 = 0;
    do {
      if (lVar9 == 0x400000) goto LAB_7101503c24;
      if (pcVar7[lVar9 + 1] == '\0') {
        lVar9 = lVar9 + 1;
        break;
      }
      lVar2 = lVar9 + 2;
      lVar9 = lVar9 + 2;
    } while (pcVar7[lVar2] != '\0');
  }
  iVar8 = (int)lVar9;
  iVar1 = (int)param_1[1] - iVar8;
  if (iVar1 == 0 || (int)param_1[1] < iVar8) {
    local_68 = (undefined1 *)0x0;
  }
  else {
    local_68 = (undefined1 *)(lVar6 + iVar8);
  }
  local_60 = 0;
  if (local_68 != (undefined1 *)0x0) {
    local_60 = iVar1;
  }
  local_98 = &local_80;
  local_68[(long)local_60 + -1] = 0;
  local_90 = 0;
  local_88 = 0;
  local_a0 = param_2;
  if (param_2 != 0) {
    uVar3 = thunk_EXT_FUN_02e95df0(param_2);
    local_90 = CONCAT44(uVar3,(int)local_90);
  }
  ppuStack_78 = &local_68;
  local_70 = 0;
  local_80 = DAT_7103a71198 + 0x10;
  *local_68 = 0;
  uVar4 = FUN_71024fd620(&local_a0,local_50,&local_54);
  if ((uVar4 & 1) != 0) {
    pcVar5 = (char *)*param_3;
    pcVar7 = (char *)0x0;
    if (local_50[0] != '\0' && local_54 != 0) {
      pcVar7 = local_50;
    }
    if ((pcVar5 == (char *)0x0) || (*pcVar5 == '\0')) {
LAB_7101503d04:
      uVar4 = 0;
    }
    else {
      uVar4 = 0;
      do {
        if (uVar4 == 0x400000) goto LAB_7101503d04;
        if (pcVar5[uVar4 + 1] == '\0') {
          uVar4 = uVar4 + 1;
          break;
        }
        lVar6 = uVar4 + 2;
        uVar4 = uVar4 + 2;
      } while (pcVar5[lVar6] != '\0');
    }
    FUN_71024fdf50((long)pcVar7,local_98,(long)pcVar5,uVar4,param_5,param_6,param_7,param_8);
  }
  uVar4 = FUN_71024fd620(&local_a0,local_50,&local_54);
  if ((uVar4 & 1) != 0) {
    pcVar5 = (char *)*param_4;
    pcVar7 = (char *)0x0;
    if (local_50[0] != '\0' && local_54 != 0) {
      pcVar7 = local_50;
    }
    if ((pcVar5 == (char *)0x0) || (*pcVar5 == '\0')) {
LAB_7101503d74:
      uVar4 = 0;
    }
    else {
      uVar4 = 0;
      do {
        if (uVar4 == 0x400000) goto LAB_7101503d74;
        if (pcVar5[uVar4 + 1] == '\0') {
          uVar4 = uVar4 + 1;
          break;
        }
        lVar6 = uVar4 + 2;
        uVar4 = uVar4 + 2;
      } while (pcVar5[lVar6] != '\0');
    }
    FUN_71024fdf50((long)pcVar7,local_98,(long)pcVar5,uVar4,param_5,param_6,param_7,param_8);
  }
  if (local_a0 != 0) {
    local_88 = 0;
    while( true ) {
      if (local_90._4_4_ <= (int)local_90) break;
      FUN_71024fd620(&local_a0,local_50,&local_54);
    }
  }
  return local_70 + iVar8;
}



void FUN_7101504bd8(long param_1)

{
  long *plVar1;
  long lVar2;
  
  lVar2 = *(long *)(param_1 + 0x20);
  if (lVar2 != 0) {
    if (*DAT_7103a65db8 == 0) {
      FUN_71005fbbd0(lVar2);
    }
    else {
      plVar1 = FUN_71024ef490(*DAT_7103a65db8,lVar2);
      if (plVar1 != (long *)0x0) {
        (**(code **)(*plVar1 + 0x38))(plVar1,lVar2);
      }
    }
    *(undefined8 *)(param_1 + 0x20) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
  }
  return;
}



undefined8 FUN_7101504c3c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a618f8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a618f8), iVar1 != 0))
  {
    *DAT_7103a618f0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a618f8);
  }
  if (param_2 != DAT_7103a618f0) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101504d3c(void)

{
  int iVar1;
  
  if (((*DAT_7103a618f8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a618f8), iVar1 != 0))
  {
    *DAT_7103a618f0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a618f8);
  }
  return DAT_7103a618f0;
}



void FUN_7101504d9c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101504ddc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



int FUN_7101504e00(long *param_1,long param_2,long *param_3,long *param_4,uint *param_5,
                  undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  long lVar2;
  undefined4 uVar3;
  ulong uVar4;
  long *plVar5;
  uint *puVar6;
  long lVar7;
  char *pcVar8;
  int iVar9;
  long lVar10;
  long local_a8;
  long *local_a0;
  undefined8 local_98;
  undefined1 local_90;
  long local_88;
  undefined1 **ppuStack_80;
  int local_78;
  undefined1 *local_70;
  int local_68;
  char local_60 [32];
  int local_24;
  
  lVar7 = *param_1;
  *(undefined1 *)((int)param_1[1] + lVar7 + -1) = 0;
  pcVar8 = (char *)*param_1;
  if ((pcVar8 == (char *)0x0) || (*pcVar8 == '\0')) {
LAB_7101504e74:
    lVar10 = 0;
  }
  else {
    lVar10 = 0;
    do {
      if (lVar10 == 0x400000) goto LAB_7101504e74;
      if (pcVar8[lVar10 + 1] == '\0') {
        lVar10 = lVar10 + 1;
        break;
      }
      lVar2 = lVar10 + 2;
      lVar10 = lVar10 + 2;
    } while (pcVar8[lVar2] != '\0');
  }
  iVar9 = (int)lVar10;
  iVar1 = (int)param_1[1] - iVar9;
  if (iVar1 == 0 || (int)param_1[1] < iVar9) {
    local_70 = (undefined1 *)0x0;
  }
  else {
    local_70 = (undefined1 *)(lVar7 + iVar9);
  }
  local_68 = 0;
  if (local_70 != (undefined1 *)0x0) {
    local_68 = iVar1;
  }
  local_a0 = &local_88;
  local_70[(long)local_68 + -1] = 0;
  local_98 = 0;
  local_90 = 0;
  plVar5 = param_4;
  puVar6 = param_5;
  local_a8 = param_2;
  if (param_2 != 0) {
    uVar3 = thunk_EXT_FUN_02e95df0(param_2);
    local_98 = CONCAT44(uVar3,(int)local_98);
  }
  ppuStack_80 = &local_70;
  local_78 = 0;
  local_88 = DAT_7103a71198 + 0x10;
  *local_70 = 0;
  uVar4 = FUN_71024fd620(&local_a8,local_60,&local_24);
  if ((uVar4 & 1) != 0) {
    plVar5 = (long *)0xffffffff;
    pcVar8 = (char *)0x0;
    if (local_60[0] != '\0' && local_24 != 0) {
      pcVar8 = local_60;
    }
    FUN_71024fdf50((long)pcVar8,local_a0,*param_3,0xffffffff,puVar6,param_6,param_7,param_8);
  }
  FUN_7101504f90(&local_a8,param_4,param_5,plVar5,puVar6,param_6,param_7,param_8);
  if (local_a8 != 0) {
    local_90 = 0;
    while( true ) {
      if (local_98._4_4_ <= (int)local_98) break;
      FUN_71024fd620(&local_a8,local_60,&local_24);
    }
  }
  return local_78 + iVar9;
}



void FUN_7101504f90(long *param_1,long *param_2,uint *param_3,undefined8 param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  ulong uVar1;
  char *pcVar2;
  undefined4 local_54;
  char local_50 [32];
  
  uVar1 = FUN_71024fd620(param_1,local_50,&local_54);
  if ((uVar1 & 1) != 0) {
    param_4 = 0xffffffff;
    pcVar2 = (char *)0x0;
    if (local_50[0] != '\0' && local_54 != 0) {
      pcVar2 = local_50;
    }
    FUN_71024fdf50((long)pcVar2,(long *)param_1[1],*param_2,0xffffffff,param_5,param_6,param_7,
                   param_8);
  }
  uVar1 = FUN_71024fd620(param_1,local_50,&local_54);
  if ((uVar1 & 1) != 0) {
    pcVar2 = (char *)0x0;
    if ((local_54 != 0) && (local_50[0] != '\0')) {
      pcVar2 = (char *)0x0;
      if (local_50[(long)local_54 + -1] != 's') {
        pcVar2 = local_50;
      }
    }
    FUN_71024fddb8((long)pcVar2,(long *)param_1[1],(ulong)*param_3,param_4,param_5,param_6,param_7,
                   param_8);
  }
  return;
}



long FUN_71015051d0(long param_1)

{
  long lVar1;
  long *plVar2;
  uint *puVar3;
  long *plVar4;
  byte *pbVar5;
  int iVar6;
  undefined8 *puVar7;
  long lVar8;
  uint uVar9;
  uint uVar10;
  
  puVar3 = DAT_7103a61900;
  if (((*DAT_7103a61908 & 1) == 0) && (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a61908), iVar6 != 0))
  {
    *puVar3 = 0x8c;
    thunk_EXT_FUN_02e95df0(DAT_7103a61908);
  }
  pbVar5 = DAT_7103a61918;
  plVar4 = DAT_7103a61910;
  uVar9 = *puVar3;
  if (uVar9 != 0x8c) {
    plVar2 = (long *)(param_1 + 0x10) + uVar9;
    if (0x8b < uVar9) {
      plVar2 = (long *)(param_1 + 0x10);
    }
    if (*plVar2 != 0) {
      return *plVar2;
    }
  }
  lVar1 = DAT_7103a59e80 + 0x10;
  uVar9 = 0;
  do {
    plVar2 = (long *)(param_1 + 0x10) + uVar9;
    if (0x8b < uVar9) {
      plVar2 = (long *)(param_1 + 0x10);
    }
    puVar7 = (undefined8 *)*plVar2;
    if (puVar7 != (undefined8 *)0x0) {
      if (((*pbVar5 & 1) == 0) && (iVar6 = thunk_EXT_FUN_02e95df0(pbVar5), iVar6 != 0)) {
        *plVar4 = lVar1;
        thunk_EXT_FUN_02e95df0(pbVar5);
      }
      lVar8 = (**(code **)*puVar7)(puVar7,plVar4);
      if (lVar8 != 0) {
        *puVar3 = uVar9;
        return lVar8;
      }
    }
    uVar10 = 0x8c;
    if ((int)uVar9 < 0x8c) {
      uVar10 = uVar9 + 1;
    }
    uVar9 = uVar10;
  } while (uVar10 != 0x8c);
  return 0;
}



undefined8 FUN_7101505310(long param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  long lVar5;
  
  lVar5 = FUN_71015051d0(*DAT_7103a59ec8);
  if ((param_2 != 0) && (uVar1 = *(uint *)(lVar5 + 0x2c), uVar1 != 0)) {
    uVar3 = 0;
    if (uVar1 != 0) {
      uVar3 = param_2 / uVar1;
    }
    uVar3 = param_2 - uVar3 * uVar1;
    uVar4 = uVar3;
    do {
      uVar2 = *(uint *)(*(long *)(lVar5 + 0x20) +
                       (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
      if (uVar2 == param_2 || uVar2 == 0) break;
      uVar2 = 0;
      if ((int)(uVar4 + 1) < (int)uVar1) {
        uVar2 = uVar4 + 1;
      }
      uVar4 = uVar2;
    } while (uVar2 != uVar3);
  }
  (**(code **)**(undefined8 **)(param_1 + 8))(*(undefined8 **)(param_1 + 8),param_2);
  return 0;
}



void FUN_71015053bc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015053fc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_710150556c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015055ac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71015056e0(long param_1,undefined8 *param_2)

{
  uint uVar1;
  uint uVar2;
  ulong uVar3;
  long lVar4;
  short *psVar5;
  uint uVar6;
  undefined1 auVar7 [16];
  undefined8 uStack_40;
  uint uStack_38;
  byte bStack_34;
  
  lVar4 = *(long *)(param_1 + 8);
  if ((lVar4 != 0) && ((*(byte *)(lVar4 + 0x14) & 0xf7) == 0xc0)) {
    uStack_38 = (uint)((ulong)*(undefined8 *)(lVar4 + 0xd) >> 0x18);
    bStack_34 = (byte)((ulong)*(undefined8 *)(lVar4 + 0xd) >> 0x38);
    psVar5 = *(short **)(lVar4 + 8);
    uStack_40._0_5_ = SUB85(psVar5,0);
    uStack_40._5_3_ = (undefined3)((ulong)psVar5 >> 0x28);
    if (((bStack_34 & 0xf7) == 0xc0) ||
       (((bStack_34 == 0xc1 || (bStack_34 == 0xc4)) || ((bStack_34 & 0xe0) == 0x20)))) {
      uVar1 = *(uint *)((long)psVar5 + (ulong)uStack_38) >> 8;
      if (*psVar5 == 0x5942) {
        uVar1 = uVar1 & 0xff00 | *(uint *)((long)psVar5 + (ulong)uStack_38) >> 0x18 |
                (uVar1 & 0xff) << 0x10;
      }
      if (uVar1 != 0) {
        uVar6 = 0;
        do {
          auVar7 = FUN_71028132dc(&uStack_40,uVar6);
          uVar2 = auVar7._12_4_ & 0xff;
          if ((uVar2 == 0xd3) || ((uVar2 == 0xd1 && (-1 < auVar7._8_4_)))) {
            uVar3 = auVar7._8_8_ & 0xffffffff;
          }
          else {
            uVar3 = 0;
          }
          (**(code **)*param_2)(param_2,uVar3,uVar6);
          uVar6 = uVar6 + 1;
        } while (uVar1 != uVar6);
      }
    }
  }
  return;
}



void FUN_7101505ae8(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101505b28. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101505be8(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101505c28. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8
FUN_7101505c50(int *param_1,long *param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5,
              undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  byte bVar3;
  long *plVar4;
  undefined8 *puVar5;
  undefined1 *puVar6;
  long lVar7;
  int *piVar8;
  ulong uVar9;
  ulong uVar10;
  uint uVar11;
  ulong uVar12;
  undefined1 *puVar13;
  undefined8 local_28;
  
  iVar1 = *param_1;
  if (iVar1 == -1) {
    return 0;
  }
  if (iVar1 == 3) {
    local_28 = *(undefined8 *)(DAT_7103a61928 + 0x18);
    plVar4 = (long *)FUN_710293d5f0(*DAT_7103a5c248,&local_28);
    if (plVar4 == (long *)0x0) {
      return 0;
    }
    iVar1 = param_1[1];
    if ((iVar1 < 0) || ((int)plVar4[1] <= iVar1)) {
      return 0;
    }
    if ((int)param_2[1] < 0x100) {
      puVar6 = (undefined1 *)*param_2;
    }
    else {
      lVar7 = *plVar4;
      *(undefined1 *)(*param_2 + (ulong)((int)param_2[1] - 1)) = 0;
      puVar5 = (undefined8 *)(*(long *)(lVar7 + 0x18) + (long)*(int *)(lVar7 + 0x20) * 0x18);
      piVar8 = (int *)*puVar5;
      uVar2 = *(uint *)((long)puVar5 + 0xc);
      uVar11 = *piVar8 << 3 | 4;
      if (uVar2 <= uVar11) {
        return 1;
      }
      lVar7 = *param_2;
      while( true ) {
        bVar3 = *(byte *)((long)piVar8 + (ulong)uVar11);
        uVar9 = (ulong)bVar3;
        if (*(int *)((long)piVar8 + uVar9 + uVar11 + 1) == iVar1) break;
        uVar11 = uVar11 + bVar3 + 5;
        if (uVar2 <= uVar11) {
          return 1;
        }
      }
      if (bVar3 != 0) {
        uVar10 = uVar9 & 3;
        if (bVar3 < 4) {
          uVar12 = 0;
        }
        else {
          uVar12 = 0;
          do {
            puVar6 = (undefined1 *)((long)piVar8 + uVar12 + (ulong)(uVar11 + 1) + 1);
            puVar13 = (undefined1 *)(lVar7 + 1 + uVar12);
            uVar12 = uVar12 + 4;
            puVar13[-1] = puVar6[-1];
            *puVar13 = *puVar6;
            puVar13[1] = puVar6[1];
            puVar13[2] = puVar6[2];
          } while ((uVar9 & 0xfc) != uVar12);
        }
        if ((bVar3 & 3) != 0) {
          puVar6 = (undefined1 *)((long)piVar8 + (uVar11 + 1) + uVar12);
          puVar13 = (undefined1 *)(lVar7 + uVar12);
          do {
            uVar10 = uVar10 - 1;
            *puVar13 = *puVar6;
            puVar6 = puVar6 + 1;
            puVar13 = puVar13 + 1;
          } while (uVar10 != 0);
        }
      }
      puVar6 = (undefined1 *)(lVar7 + uVar9);
    }
    *puVar6 = 0;
  }
  else {
    FUN_7100bc08f0(param_2,*(undefined8 *)(DAT_7103a61920 + (long)iVar1 * 8),(ulong)(uint)param_1[1]
                   ,param_4,param_5,param_6,param_7,param_8);
  }
  return 1;
}



undefined4
FUN_7101505e20(int *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
              undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  byte bVar2;
  long *plVar3;
  long *plVar4;
  int iVar5;
  undefined8 *puVar6;
  long lVar7;
  ulong uVar8;
  int *piVar9;
  uint *puVar10;
  ulong uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  ulong uVar15;
  byte *pbVar16;
  byte *pbVar17;
  byte *local_158;
  int local_150;
  byte local_14c [255];
  undefined1 local_4d;
  undefined8 local_48;
  
  lVar7 = DAT_7103a61928;
  plVar4 = DAT_7103a5c248;
  if (*param_1 == -1) {
    return 0xffffffff;
  }
  local_158 = *(byte **)(DAT_7103a61928 + (long)*param_1 * 8);
  plVar3 = (long *)FUN_710293d5f0(*DAT_7103a5c248,&local_158);
  if (plVar3 != (long *)0x0) {
    iVar1 = *param_1;
    local_158 = local_14c;
    local_4d = 0;
    local_150 = 0x100;
    local_14c[0] = 0;
    if (iVar1 == -1) {
      return 0xffffffff;
    }
    if (iVar1 == 3) {
      local_48 = *(undefined8 *)(lVar7 + 0x18);
      plVar4 = (long *)FUN_710293d5f0(*plVar4,&local_48);
      if (plVar4 == (long *)0x0) {
        return 0xffffffff;
      }
      iVar1 = param_1[1];
      if (iVar1 < 0) {
        return 0xffffffff;
      }
      if ((int)plVar4[1] <= iVar1) {
        return 0xffffffff;
      }
      if (local_150 < 0x100) {
        *local_158 = 0;
      }
      else {
        lVar7 = *plVar4;
        local_158[local_150 - 1] = 0;
        puVar6 = (undefined8 *)(*(long *)(lVar7 + 0x18) + (long)*(int *)(lVar7 + 0x20) * 0x18);
        piVar9 = (int *)*puVar6;
        uVar14 = *(uint *)((long)puVar6 + 0xc);
        uVar12 = *piVar9 << 3 | 4;
        if (uVar12 < uVar14) {
LAB_7101505f24:
          bVar2 = *(byte *)((long)piVar9 + (ulong)uVar12);
          uVar8 = (ulong)bVar2;
          if (*(int *)((long)piVar9 + uVar8 + uVar12 + 1) != iVar1) goto code_r0x007101505f40;
          if (bVar2 != 0) {
            uVar11 = uVar8 & 3;
            if (bVar2 < 4) {
              uVar15 = 0;
            }
            else {
              uVar15 = 0;
              do {
                pbVar16 = (byte *)((long)piVar9 + uVar15 + (ulong)(uVar12 + 1) + 1);
                pbVar17 = local_158 + uVar15 + 1;
                uVar15 = uVar15 + 4;
                pbVar17[-1] = pbVar16[-1];
                *pbVar17 = *pbVar16;
                pbVar17[1] = pbVar16[1];
                pbVar17[2] = pbVar16[2];
              } while ((uVar8 & 0xfc) != uVar15);
            }
            if ((bVar2 & 3) != 0) {
              pbVar16 = (byte *)((long)piVar9 + (uVar12 + 1) + uVar15);
              pbVar17 = local_158 + uVar15;
              do {
                uVar11 = uVar11 - 1;
                *pbVar17 = *pbVar16;
                pbVar16 = pbVar16 + 1;
                pbVar17 = pbVar17 + 1;
              } while (uVar11 != 0);
            }
          }
          local_158[uVar8] = 0;
        }
      }
    }
    else {
      FUN_7100bc08f0((long *)&local_158,*(undefined8 *)(DAT_7103a61920 + (long)iVar1 * 8),
                     (ulong)(uint)param_1[1],param_4,param_5,param_6,param_7,param_8);
    }
LAB_7101505f78:
    local_158[(long)local_150 + -1] = 0;
    iVar1 = *(int *)(*plVar3 + 0x20);
    if (iVar1 == -1) {
      return 0xfffffffe;
    }
    lVar7 = 0;
    do {
      pbVar16 = local_158 + lVar7;
      lVar7 = lVar7 + 1;
    } while (*pbVar16 != 0);
    uVar14 = (uint)*local_158;
    puVar10 = *(uint **)(*(long *)(*plVar3 + 0x18) + (long)iVar1 * 0x18);
    uVar12 = *puVar10;
    if (*local_158 == 0) {
      uVar13 = 0;
    }
    else {
      uVar13 = 0;
      pbVar16 = local_158;
      do {
        pbVar16 = pbVar16 + 1;
        uVar13 = uVar14 + uVar13 * 0x492;
        uVar14 = (uint)*pbVar16;
      } while (uVar14 != 0);
    }
    uVar14 = 0;
    if (uVar12 != 0) {
      uVar14 = uVar13 / uVar12;
    }
    iVar1 = uVar13 - uVar14 * uVar12;
    if (puVar10[(int)(iVar1 * 2 | 1)] != 0) {
      uVar12 = 0;
      iVar5 = (int)lVar7;
      uVar14 = puVar10[iVar1 * 2 + 2];
      do {
        bVar2 = *(byte *)((long)puVar10 + (ulong)uVar14);
        if (bVar2 + 1 == iVar5) {
          lVar7 = (ulong)uVar14 + 1;
          if (iVar5 + -1 < 1) {
LAB_710150609c:
            return *(undefined4 *)((long)puVar10 + lVar7 + (ulong)(uint)bVar2);
          }
          pbVar16 = local_158;
          uVar8 = (ulong)(iVar5 - 1);
          pbVar17 = (byte *)((long)puVar10 + lVar7);
          while( true ) {
            if (*pbVar16 != *pbVar17) break;
            uVar8 = uVar8 - 1;
            pbVar16 = pbVar16 + 1;
            pbVar17 = pbVar17 + 1;
            if (uVar8 == 0) goto LAB_710150609c;
          }
        }
        uVar12 = uVar12 + 1;
        uVar14 = uVar14 + bVar2 + 5;
        if (uVar12 == puVar10[(int)(iVar1 * 2 | 1)]) {
          return 0xffffffff;
        }
      } while( true );
    }
  }
  return 0xffffffff;
code_r0x007101505f40:
  uVar12 = uVar12 + bVar2 + 5;
  if (uVar14 <= uVar12) goto LAB_7101505f78;
  goto LAB_7101505f24;
}



long FUN_7101506144(int *param_1,undefined8 *param_2)

{
  long *plVar1;
  long lVar2;
  undefined8 local_8;
  
  if (*param_1 != -1) {
    local_8 = *(undefined8 *)(&DAT_7103e37af0 + (long)*param_1 * 8);
    plVar1 = (long *)FUN_710293d5f0(*DAT_7103a5c248,&local_8);
    if (plVar1 != (long *)0x0) {
      lVar2 = FUN_7101d92260(plVar1,param_2);
      return lVar2;
    }
  }
  return 0;
}



uint FUN_7101506700(int *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  byte bVar3;
  uint uVar4;
  long *plVar5;
  long *plVar6;
  undefined8 *puVar7;
  long lVar8;
  ulong uVar9;
  int *piVar10;
  byte *pbVar11;
  ulong uVar12;
  ulong uVar13;
  byte *pbVar14;
  byte *local_158;
  int local_150;
  byte local_14c [255];
  undefined1 local_4d;
  undefined8 local_48;
  
  lVar8 = DAT_7103a61928;
  plVar6 = DAT_7103a5c248;
  if (*param_1 == -1) {
    return 0;
  }
  local_158 = *(byte **)(DAT_7103a61928 + (long)*param_1 * 8);
  plVar5 = (long *)FUN_710293d5f0(*DAT_7103a5c248,&local_158);
  uVar4 = 0;
  if (plVar5 == (long *)0x0) goto LAB_7101506914;
  local_158 = local_14c;
  local_4d = 0;
  local_14c[0] = 0;
  local_150 = 0x100;
  iVar1 = *param_1;
  if (iVar1 == -1) {
LAB_710150683c:
    uVar4 = 0;
  }
  else {
    if (iVar1 == 3) {
      local_48 = *(undefined8 *)(lVar8 + 0x18);
      plVar6 = (long *)FUN_710293d5f0(*plVar6,&local_48);
      uVar4 = 0;
      if (plVar6 == (long *)0x0) goto LAB_7101506914;
      iVar1 = param_1[1];
      if ((iVar1 < 0) || ((int)plVar6[1] <= iVar1)) goto LAB_710150683c;
      if (local_150 < 0x100) {
        *local_158 = 0;
      }
      else {
        lVar8 = *plVar6;
        local_158[local_150 - 1] = 0;
        puVar7 = (undefined8 *)(*(long *)(lVar8 + 0x18) + (long)*(int *)(lVar8 + 0x20) * 0x18);
        piVar10 = (int *)*puVar7;
        uVar2 = *(uint *)((long)puVar7 + 0xc);
        uVar4 = *piVar10 << 3 | 4;
        if (uVar4 < uVar2) {
LAB_7101506804:
          bVar3 = *(byte *)((long)piVar10 + (ulong)uVar4);
          uVar9 = (ulong)bVar3;
          if (*(int *)((long)piVar10 + uVar9 + uVar4 + 1) != iVar1) goto code_r0x007101506820;
          if (bVar3 != 0) {
            uVar12 = uVar9 & 3;
            if (bVar3 < 4) {
              uVar13 = 0;
            }
            else {
              uVar13 = 0;
              do {
                pbVar11 = (byte *)((long)piVar10 + uVar13 + (ulong)(uVar4 + 1) + 1);
                pbVar14 = local_158 + uVar13 + 1;
                uVar13 = uVar13 + 4;
                pbVar14[-1] = pbVar11[-1];
                *pbVar14 = *pbVar11;
                pbVar14[1] = pbVar11[1];
                pbVar14[2] = pbVar11[2];
              } while ((uVar9 & 0xfc) != uVar13);
            }
            if ((bVar3 & 3) != 0) {
              pbVar11 = (byte *)((long)piVar10 + (uVar4 + 1) + uVar13);
              pbVar14 = local_158 + uVar13;
              do {
                uVar12 = uVar12 - 1;
                *pbVar14 = *pbVar11;
                pbVar11 = pbVar11 + 1;
                pbVar14 = pbVar14 + 1;
              } while (uVar12 != 0);
            }
          }
          local_158[uVar9] = 0;
        }
      }
    }
    else {
      FUN_7100bc08f0((long *)&local_158,*(undefined8 *)(DAT_7103a61920 + (long)iVar1 * 8),
                     (ulong)(uint)param_1[1],param_4,param_5,param_6,param_7,param_8);
    }
LAB_7101506860:
    pbVar11 = local_158;
    local_158[(long)local_150 + -1] = 0;
    if (local_158 == (byte *)0x0) {
LAB_71015068a8:
      uVar9 = 0;
    }
    else {
      uVar9 = (ulong)*local_158;
      if (*local_158 != 0) {
        uVar9 = 0;
        do {
          if (uVar9 == 0x400000) goto LAB_71015068a8;
          if (local_158[uVar9 + 1] == 0) {
            uVar9 = uVar9 + 1;
            break;
          }
          lVar8 = uVar9 + 2;
          uVar9 = uVar9 + 2;
        } while (local_158[lVar8] != 0);
      }
    }
    uVar4 = (uint)uVar9 & ((int)(uint)uVar9 >> 0x1f ^ 0xffffffffU);
    uVar2 = 4;
    if ((int)(local_150 - uVar4) < 5) {
      uVar2 = local_150 + ~uVar4;
    }
    if (0 < (int)uVar2) {
      thunk_EXT_FUN_02e95df0(local_158 + uVar4,&DAT_71030d2870,(ulong)uVar2);
      pbVar11[(ulong)uVar2 + (ulong)uVar4] = 0;
    }
    local_158[(long)local_150 + -1] = 0;
    uVar4 = FUN_710293e5e0(plVar5,local_158);
  }
LAB_7101506914:
  return uVar4 & 1;
code_r0x007101506820:
  uVar4 = uVar4 + bVar3 + 5;
  if (uVar2 <= uVar4) goto LAB_7101506860;
  goto LAB_7101506804;
}



void FUN_71015069d0(long *param_1,int *param_2,long param_3,undefined8 param_4,undefined8 *param_5,
                   undefined8 *param_6,undefined8 param_7,undefined8 param_8,undefined8 param_9)

{
  int iVar1;
  uint uVar2;
  byte bVar3;
  long *plVar4;
  long *plVar5;
  byte *pbVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  long lVar9;
  ulong uVar10;
  int *piVar11;
  byte *pbVar12;
  ulong uVar13;
  uint uVar14;
  ulong uVar15;
  int local_1a0;
  undefined4 uStack_19c;
  byte *local_198 [4];
  byte *local_178;
  int local_170;
  byte local_16c [255];
  undefined1 local_6d;
  
  lVar9 = DAT_7103a61928;
  plVar5 = DAT_7103a5c248;
  if (*param_2 != -1) {
    local_178 = *(byte **)(DAT_7103a61928 + (long)*param_2 * 8);
    puVar8 = param_5;
    puVar7 = param_6;
    plVar4 = (long *)FUN_710293d5f0(*DAT_7103a5c248,&local_178);
    if (plVar4 != (long *)0x0) {
      local_178 = local_16c;
      local_6d = 0;
      local_16c[0] = 0;
      local_170 = 0x100;
      iVar1 = *param_2;
      if (iVar1 != -1) {
        if (iVar1 == 3) {
          local_198[0] = *(byte **)(lVar9 + 0x18);
          plVar5 = (long *)FUN_710293d5f0(*plVar5,local_198);
          if (((plVar5 == (long *)0x0) || (iVar1 = param_2[1], iVar1 < 0)) ||
             ((int)plVar5[1] <= iVar1)) goto LAB_7101506b20;
          if (local_170 < 0x100) {
            *local_178 = 0;
          }
          else {
            lVar9 = *plVar5;
            local_178[local_170 - 1] = 0;
            puVar8 = (undefined8 *)(*(long *)(lVar9 + 0x18) + (long)*(int *)(lVar9 + 0x20) * 0x18);
            piVar11 = (int *)*puVar8;
            uVar2 = *(uint *)((long)puVar8 + 0xc);
            uVar14 = *piVar11 << 3 | 4;
            if (uVar14 < uVar2) {
LAB_7101506af0:
              bVar3 = *(byte *)((long)piVar11 + (ulong)uVar14);
              uVar10 = (ulong)bVar3;
              if (*(int *)((long)piVar11 + uVar10 + uVar14 + 1) != iVar1) goto code_r0x007101506b0c;
              if (bVar3 != 0) {
                uVar13 = uVar10 & 3;
                if (bVar3 < 4) {
                  uVar15 = 0;
                }
                else {
                  uVar15 = 0;
                  do {
                    pbVar12 = (byte *)((long)piVar11 + uVar15 + (ulong)(uVar14 + 1) + 1);
                    pbVar6 = local_178 + uVar15 + 1;
                    uVar15 = uVar15 + 4;
                    pbVar6[-1] = pbVar12[-1];
                    *pbVar6 = *pbVar12;
                    pbVar6[1] = pbVar12[1];
                    pbVar6[2] = pbVar12[2];
                  } while ((uVar10 & 0xfc) != uVar15);
                }
                if ((bVar3 & 3) != 0) {
                  pbVar12 = (byte *)((long)piVar11 + (uVar14 + 1) + uVar15);
                  pbVar6 = local_178 + uVar15;
                  do {
                    uVar13 = uVar13 - 1;
                    *pbVar6 = *pbVar12;
                    pbVar12 = pbVar12 + 1;
                    pbVar6 = pbVar6 + 1;
                  } while (uVar13 != 0);
                }
              }
              local_178[uVar10] = 0;
            }
          }
        }
        else {
          FUN_7100bc08f0((long *)&local_178,*(undefined8 *)(DAT_7103a61920 + (long)iVar1 * 8),
                         (ulong)(uint)param_2[1],puVar8,puVar7,param_7,param_8,param_9);
        }
LAB_7101506b6c:
        pbVar12 = local_178;
        local_178[(long)local_170 + -1] = 0;
        if (local_178 == (byte *)0x0) {
LAB_7101506bb4:
          uVar10 = 0;
        }
        else {
          uVar10 = (ulong)*local_178;
          if (*local_178 != 0) {
            uVar10 = 0;
            do {
              if (uVar10 == 0x400000) goto LAB_7101506bb4;
              if (local_178[uVar10 + 1] == 0) {
                uVar10 = uVar10 + 1;
                break;
              }
              lVar9 = uVar10 + 2;
              uVar10 = uVar10 + 2;
            } while (local_178[lVar9] != 0);
          }
        }
        pbVar6 = (byte *)*param_6;
        uVar14 = (uint)uVar10 & ((int)(uint)uVar10 >> 0x1f ^ 0xffffffffU);
        if (pbVar6 == (byte *)0x0) {
LAB_7101506c04:
          uVar10 = 0;
        }
        else {
          uVar10 = (ulong)*pbVar6;
          if (*pbVar6 != 0) {
            uVar10 = 0;
            do {
              if (uVar10 == 0x400000) goto LAB_7101506c04;
              if (pbVar6[uVar10 + 1] == 0) {
                uVar10 = uVar10 + 1;
                break;
              }
              lVar9 = uVar10 + 2;
              uVar10 = uVar10 + 2;
            } while (pbVar6[lVar9] != 0);
          }
        }
        iVar1 = (int)uVar10;
        if ((int)(local_170 - uVar14) <= (int)uVar10) {
          iVar1 = local_170 + ~uVar14;
        }
        if (0 < iVar1) {
          thunk_EXT_FUN_02e95df0(local_178 + uVar14,pbVar6,iVar1);
          pbVar12[(int)(iVar1 + uVar14)] = 0;
        }
        if (param_3 == 0) {
          local_1a0 = -1;
          uStack_19c = 0xffffffff;
        }
        else {
          local_1a0 = *(int *)(param_3 + 0x400);
          uStack_19c = *(undefined4 *)(param_3 + 0x404);
        }
        FUN_7101da8240((uint *)local_198,&local_1a0);
        local_178[(long)local_170 + -1] = 0;
        FUN_7101d9f0d0(param_1,plVar4,(long *)&local_178,local_198,param_4,param_5,param_7,param_8,
                       param_9);
        return;
      }
    }
  }
LAB_7101506b20:
  *param_1 = 0;
  *(undefined4 *)(param_1 + 1) = 0;
  param_1[2] = -1;
  return;
code_r0x007101506b0c:
  uVar14 = uVar14 + bVar3 + 5;
  if (uVar2 <= uVar14) goto LAB_7101506b6c;
  goto LAB_7101506af0;
}



undefined8 FUN_7101507410(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a61940 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61940), iVar1 != 0))
  {
    *DAT_7103a61938 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61940);
  }
  if (param_2 != DAT_7103a61938) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101507510(void)

{
  int iVar1;
  
  if (((*DAT_7103a61940 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61940), iVar1 != 0))
  {
    *DAT_7103a61938 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61940);
  }
  return DAT_7103a61938;
}



void FUN_7101507580(undefined8 *param_1)

{
  long *plVar1;
  
  *param_1 = &DAT_7103959b58;
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015075cc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_710150765c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710150769c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 FUN_7101508030(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a61960 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61960), iVar1 != 0))
  {
    *DAT_7103a61958 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61960);
  }
  if (param_2 != DAT_7103a61958) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101508130(void)

{
  int iVar1;
  
  if (((*DAT_7103a61960 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61960), iVar1 != 0))
  {
    *DAT_7103a61958 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61960);
  }
  return DAT_7103a61958;
}



void FUN_7101508190(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015081d0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71015081f0(undefined8 *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  long *plVar6;
  int iVar7;
  undefined8 *puVar8;
  long lVar9;
  
  param_1[1] = 0;
  plVar6 = DAT_7103a59ec8;
  *param_1 = &DAT_7103959c90;
  puVar8 = *(undefined8 **)(*plVar6 + 0x28);
  if (puVar8 != (undefined8 *)0x0) {
    if (((*DAT_7103a61988 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)
       ) {
      *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a61988);
    }
    lVar9 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
    if (((lVar9 != 0) && (uVar1 = *param_2, uVar1 != 0)) &&
       (uVar2 = *(uint *)(lVar9 + 0x34), uVar2 != 0)) {
      uVar4 = 0;
      if (uVar2 != 0) {
        uVar4 = uVar1 / uVar2;
      }
      uVar4 = uVar1 - uVar4 * uVar2;
      uVar5 = uVar4;
      do {
        uVar3 = *(uint *)(*(long *)(lVar9 + 0x28) +
                         (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
        if (uVar3 == uVar1) {
          lVar9 = *(long *)(*(long *)(lVar9 + 0x28) + (long)(int)uVar5 * 0x10 + 8);
          if (lVar9 == 0) {
            return;
          }
          param_1[1] = lVar9;
          return;
        }
        if (uVar3 == 0) {
          return;
        }
        uVar3 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar3 = uVar5 + 1;
        }
        uVar5 = uVar3;
      } while (uVar3 != uVar4);
    }
  }
  return;
}



void FUN_7101508310(undefined8 *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  long *plVar6;
  byte *pbVar7;
  int iVar8;
  undefined8 *puVar9;
  long lVar10;
  uint *puVar11;
  
  pbVar7 = DAT_7103a61988;
  plVar6 = DAT_7103a59ec8;
  puVar9 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
  lVar10 = 0;
  if (puVar9 != (undefined8 *)0x0) {
    if (((*DAT_7103a61988 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar8 != 0)
       ) {
      *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a61988);
    }
    lVar10 = (**(code **)*puVar9)(puVar9,DAT_7103a61980);
  }
  puVar11 = DAT_7103a5d098;
  if ((-1 < (int)param_2) && ((int)param_2 < *(int *)(lVar10 + 0x78))) {
    puVar11 = (uint *)(*(long *)(*(long *)(lVar10 + 0x80) + (ulong)param_2 * 8) + 0x50);
  }
  *param_1 = &DAT_7103959c90;
  param_1[1] = 0;
  puVar9 = *(undefined8 **)(*plVar6 + 0x28);
  if (puVar9 != (undefined8 *)0x0) {
    if (((*pbVar7 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar8 != 0)) {
      *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a61988);
    }
    lVar10 = (**(code **)*puVar9)(puVar9,DAT_7103a61980);
    if (((lVar10 != 0) && (uVar1 = *puVar11, uVar1 != 0)) &&
       (uVar2 = *(uint *)(lVar10 + 0x34), uVar2 != 0)) {
      uVar4 = 0;
      if (uVar2 != 0) {
        uVar4 = uVar1 / uVar2;
      }
      uVar4 = uVar1 - uVar4 * uVar2;
      uVar5 = uVar4;
      do {
        uVar3 = *(uint *)(*(long *)(lVar10 + 0x28) +
                         (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
        if (uVar3 == uVar1) {
          lVar10 = *(long *)(*(long *)(lVar10 + 0x28) + (long)(int)uVar5 * 0x10 + 8);
          if (lVar10 == 0) {
            return;
          }
          param_1[1] = lVar10;
          return;
        }
        if (uVar3 == 0) {
          return;
        }
        uVar3 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar3 = uVar5 + 1;
        }
        uVar5 = uVar3;
      } while (uVar3 != uVar4);
    }
  }
  return;
}



uint FUN_7101508548(long param_1,undefined4 param_2)

{
  uint uVar1;
  long *plVar2;
  undefined *local_30;
  undefined8 uStack_28;
  undefined4 local_20;
  undefined1 local_1c;
  undefined4 local_18;
  undefined8 uVar3;
  
  plVar2 = *(long **)(param_1 + 8);
  uVar1 = 0;
  if (plVar2 != (long *)0x0) {
    *(undefined1 *)((long)(int)plVar2[1] + *plVar2 + -1) = 0;
    if (*(char *)*plVar2 == '\0') {
      return 0;
    }
    local_20 = 0;
    local_1c = 0;
    local_30 = &DAT_7103959c70;
    uStack_28 = 0;
    local_18 = 0;
    uVar3 = FUN_710150b4e4(plVar2,(long)&local_30,param_2);
    uVar1 = (uint)uVar3;
  }
  return uVar1 & 1;
}



uint FUN_71015085b4(long param_1)

{
  uint uVar1;
  short *psVar2;
  uint uVar3;
  long lVar4;
  long lVar5;
  
  if ((*(long *)(param_1 + 8) != 0) &&
     (uVar3 = *(uint *)(*(long *)(param_1 + 8) + 100), -1 < (int)uVar3)) {
    lVar5 = 0x460;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1d) {
      lVar5 = 0;
    }
    lVar4 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar5 + 0x20);
    lVar5 = *(long *)(lVar4 + 0x28);
    if (*(uint *)(lVar4 + 0x20) <= uVar3) {
      uVar3 = 0;
    }
    if ((*(byte *)(lVar5 + (ulong)uVar3 * 0x48 + 0x14) & 0xf7) == 0xc0) {
      lVar5 = lVar5 + (ulong)uVar3 * 0x48;
      psVar2 = *(short **)(lVar5 + 8);
      uVar1 = *(uint *)((long)psVar2 + (ulong)*(uint *)(lVar5 + 0x10));
      uVar3 = uVar1 >> 8;
      if (*psVar2 == 0x5942) {
        uVar3 = uVar3 & 0xff00 | uVar1 >> 0x18 | (uVar3 & 0xff) << 0x10;
      }
    }
    else {
      uVar3 = 0;
    }
    if (0x10 < uVar3) {
      uVar3 = 0x11;
    }
    return uVar3;
  }
  return 0;
}



bool FUN_7101508674(long param_1)

{
  uint uVar1;
  long lVar2;
  
  if ((*(long *)(param_1 + 8) != 0) &&
     (uVar1 = *(uint *)(*(long *)(param_1 + 8) + 100), -1 < (int)uVar1)) {
    lVar2 = 0x460;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1d) {
      lVar2 = 0;
    }
    lVar2 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar2 + 0x20);
    if (*(uint *)(lVar2 + 0x20) <= uVar1) {
      uVar1 = 0;
    }
    return *(char *)(*(long *)(lVar2 + 0x28) + (ulong)uVar1 * 0x48 + 0x42) != '\0';
  }
  return false;
}



bool FUN_71015088a0(long param_1,long *param_2,int param_3,undefined8 param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  uint uVar4;
  long *plVar5;
  ulong uVar6;
  long lVar7;
  byte *pbVar8;
  
  if (param_2 == (long *)0x0) goto LAB_71015089e0;
  plVar5 = *(long **)(param_1 + 8);
  uVar1 = (uint)param_4;
  if (plVar5 == (long *)0x0) {
    plVar5 = &DAT_7103878ff0;
  }
  else {
    *(undefined1 *)((long)(int)plVar5[1] + *plVar5 + -1) = 0;
  }
  pbVar8 = (byte *)*param_2;
  pbVar3 = (byte *)*plVar5;
  if (pbVar8 != pbVar3) {
    if (pbVar3 == (byte *)0x0) {
LAB_7101508934:
      uVar6 = 0;
    }
    else {
      uVar6 = (ulong)*pbVar3;
      if (*pbVar3 != 0) {
        uVar6 = 0;
        do {
          if (uVar6 == 0x400000) goto LAB_7101508934;
          if (pbVar3[uVar6 + 1] == 0) {
            uVar6 = uVar6 + 1;
            break;
          }
          lVar7 = uVar6 + 2;
          uVar6 = uVar6 + 2;
        } while (pbVar3[lVar7] != 0);
      }
    }
    iVar2 = (int)uVar6;
    if ((int)param_2[1] <= (int)uVar6) {
      iVar2 = (int)param_2[1] + -1;
    }
    thunk_EXT_FUN_02e95df0(pbVar8,pbVar3,(long)iVar2);
    pbVar8[iVar2] = 0;
  }
  if ((*(long *)(param_1 + 8) == 0) ||
     (uVar4 = *(uint *)(*(long *)(param_1 + 8) + 100), (int)uVar4 < 0)) {
LAB_71015089cc:
    uVar1 = uVar1 & ((int)uVar1 >> 0x1f ^ 0xffffffffU);
  }
  else {
    lVar7 = 0x460;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1d) {
      lVar7 = 0;
    }
    lVar7 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar7 + 0x20);
    if (*(uint *)(lVar7 + 0x20) <= uVar4) {
      uVar4 = 0;
    }
    if (*(char *)(*(long *)(lVar7 + 0x28) + (ulong)uVar4 * 0x48 + 0x42) == '\0')
    goto LAB_71015089cc;
    uVar1 = param_3 + 1;
  }
  FUN_7100df1000(param_2,"_%02d",(ulong)uVar1,param_4,param_5,param_6,param_7,param_8);
LAB_71015089e0:
  return param_2 != (long *)0x0;
}



bool FUN_7101508a04(long param_1,long param_2)

{
  bool bVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  
  lVar4 = *(long *)(param_1 + 8);
  if (lVar4 == 0) {
    iVar2 = -1;
    lVar3 = *(long *)(param_2 + 8);
    if (lVar3 == 0) goto LAB_7101508a48;
LAB_7101508a2c:
    if (iVar2 == *(int *)(lVar3 + 0x54)) {
      return false;
    }
  }
  else {
    iVar2 = *(int *)(lVar4 + 0x54);
    lVar3 = *(long *)(param_2 + 8);
    if (lVar3 != 0) goto LAB_7101508a2c;
LAB_7101508a48:
    if (iVar2 == -1) {
      return false;
    }
  }
  if (lVar4 == 0) {
    return true;
  }
  switch(*(undefined4 *)(lVar4 + 0x54)) {
  case 0:
    if (lVar3 == 0) {
      return true;
    }
    if (*(int *)(lVar3 + 0x54) - 1U < 6) {
      return false;
    }
    return true;
  case 1:
    if ((lVar3 != 0) && (*(uint *)(lVar3 + 0x54) < 4)) {
      return (*(uint *)(lVar3 + 0x54) & 0xf) == 1;
    }
    break;
  case 2:
  case 3:
    if ((lVar3 != 0) && (*(uint *)(lVar3 + 0x54) < 2)) {
      return false;
    }
    break;
  case 4:
  case 5:
    if ((lVar3 != 0) && (*(int *)(lVar3 + 0x54) == 0)) {
      return false;
    }
    break;
  case 6:
    if (lVar3 == 0) {
      return true;
    }
    if (*(int *)(lVar3 + 0x54) == 0) {
      return false;
    }
    if (*(int *)(lVar3 + 0x54) != 7) {
      return true;
    }
    bVar1 = FUN_710150bcdc(lVar4);
    if (!bVar1) {
      return true;
    }
    lVar4 = *(long *)(param_2 + 8);
    goto joined_r0x007101508b28;
  case 7:
    if (lVar3 == 0) {
      return true;
    }
    if (*(int *)(lVar3 + 0x54) != 6) {
      return true;
    }
    bVar1 = FUN_710150bcdc(lVar3);
    if (!bVar1) {
      return true;
    }
    lVar4 = *(long *)(param_1 + 8);
joined_r0x007101508b28:
    if ((lVar4 != 0) && (iVar2 = FUN_710150bc7c(lVar4), iVar2 - 3U < 3)) {
      return false;
    }
  }
  return true;
}



undefined8 FUN_7101508b4c(long param_1,undefined4 param_2)

{
  uint uVar1;
  long *plVar2;
  long lVar3;
  long lVar4;
  
  switch(param_2) {
  case 0x1b:
    plVar2 = *(long **)(param_1 + 8);
    if (*(int *)((long)plVar2 + 0x54) != 2) {
      return 0;
    }
    break;
  case 0x1c:
    plVar2 = *(long **)(param_1 + 8);
    if (*(int *)((long)plVar2 + 0x54) != 3) {
      return 0;
    }
    break;
  case 0x1d:
    plVar2 = *(long **)(param_1 + 8);
    if (*(int *)((long)plVar2 + 0x54) != 1) {
      return 0;
    }
    break;
  case 0x1e:
    plVar2 = *(long **)(param_1 + 8);
    if (*(int *)((long)plVar2 + 0x54) != 0) {
      return 0;
    }
    break;
  case 0x1f:
    plVar2 = *(long **)(param_1 + 8);
    if (*(int *)((long)plVar2 + 0x54) != 7) {
      return 0;
    }
    break;
  case 0x20:
    plVar2 = *(long **)(param_1 + 8);
    if (*(int *)((long)plVar2 + 0x54) != 4) {
      return 0;
    }
    break;
  case 0x21:
    plVar2 = *(long **)(param_1 + 8);
    if (*(int *)((long)plVar2 + 0x54) != 5) {
      return 0;
    }
    break;
  case 0x22:
    plVar2 = *(long **)(param_1 + 8);
    if (*(int *)((long)plVar2 + 0x54) != 6) {
      return 0;
    }
    break;
  default:
    return 0;
  }
  *(undefined1 *)((long)(int)plVar2[1] + *plVar2 + -1) = 0;
  if ((*(char *)*plVar2 != '\0') && (uVar1 = *(uint *)(plVar2 + 0xc), -1 < (int)uVar1)) {
    lVar3 = 0x438;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1c) {
      lVar3 = 0;
    }
    lVar4 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar3 + 0x20);
    lVar3 = *(long *)(lVar4 + 0x28);
    if (lVar3 != 0) {
      if (*(uint *)(lVar4 + 0x20) <= uVar1) {
        uVar1 = 0;
      }
      if (((*(char *)(lVar3 + (ulong)uVar1 * 0x24 + 0x1e) == '\0') &&
          (lVar3 = FUN_710150bbfc(*(long **)(param_1 + 8)), *(int *)(lVar3 + 0xc) == 0)) &&
         (*(int *)(*(long *)(param_1 + 8) + 0x68) - 4U < 0xfffffffd)) {
        return 1;
      }
    }
  }
  return 0;
}



bool FUN_7101508cdc(long param_1)

{
  long *plVar1;
  long lVar2;
  uint uVar3;
  long lVar4;
  
  plVar1 = *(long **)(param_1 + 8);
  if (((plVar1 != (long *)0x0) &&
      (*(undefined1 *)((long)(int)plVar1[1] + *plVar1 + -1) = 0, *(char *)*plVar1 != '\0')) &&
     (uVar3 = *(uint *)(plVar1 + 0xc), -1 < (int)uVar3)) {
    lVar2 = 0x438;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1c) {
      lVar2 = 0;
    }
    lVar2 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar2 + 0x20);
    lVar4 = *(long *)(lVar2 + 0x28);
    if (lVar4 != 0) {
      if (*(uint *)(lVar2 + 0x20) <= uVar3) {
        uVar3 = 0;
      }
      if (*(char *)(lVar4 + (ulong)uVar3 * 0x24 + 0x1e) == '\0') {
        plVar1 = *(long **)(param_1 + 8);
        *(undefined1 *)((long)(int)plVar1[1] + *plVar1 + -1) = 0;
        uVar3 = *(uint *)(plVar1 + 0xc);
        lVar2 = 0x438;
        if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1c) {
          lVar2 = 0;
        }
        lVar2 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar2 + 0x20);
        if (*(uint *)(lVar2 + 0x20) <= uVar3) {
          uVar3 = 0;
        }
        if (*(int *)(*(long *)(lVar2 + 0x28) + (ulong)uVar3 * 0x24 + 0xc) == 0) {
          return *(int *)(*(long *)(param_1 + 8) + 0x68) - 4U < 0xfffffffd;
        }
      }
    }
  }
  return false;
}



void FUN_7101508de8(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101508e28. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



ulong FUN_7101508e50(long *param_1,long *param_2)

{
  int iVar1;
  long lVar2;
  uint uVar3;
  ulong uVar4;
  byte *pbVar5;
  long alStack_e0 [6];
  byte *local_b0;
  int local_a8;
  byte local_a4 [127];
  undefined1 local_25;
  
  (**(code **)(*param_2 + 0x10))(alStack_e0);
  local_25 = 0;
  local_b0 = local_a4;
  local_a8 = 0x80;
  local_a4[0] = 0;
  uVar3 = FUN_71015093d0((long *)&local_b0,0x710310a344,alStack_e0);
  uVar4 = (ulong)uVar3;
  *(undefined4 *)(param_1 + 1) = 0x80;
  *param_1 = (long)param_1 + 0xc;
  *(undefined1 *)((long)param_1 + 0x8b) = 0;
  local_b0[(long)local_a8 + -1] = 0;
  pbVar5 = (byte *)*param_1;
  if (pbVar5 != local_b0) {
    if (local_b0 == (byte *)0x0) {
LAB_7101508f08:
      uVar4 = 0;
    }
    else {
      uVar4 = (ulong)*local_b0;
      if (*local_b0 != 0) {
        uVar4 = 0;
        do {
          if (uVar4 == 0x400000) goto LAB_7101508f08;
          if (local_b0[uVar4 + 1] == 0) {
            uVar4 = uVar4 + 1;
            break;
          }
          lVar2 = uVar4 + 2;
          uVar4 = uVar4 + 2;
        } while (local_b0[lVar2] != 0);
      }
    }
    iVar1 = (int)uVar4;
    if ((int)param_1[1] <= (int)uVar4) {
      iVar1 = (int)param_1[1] + -1;
    }
    uVar4 = thunk_EXT_FUN_02e95df0(pbVar5,local_b0,(long)iVar1);
    pbVar5[iVar1] = 0;
  }
  return uVar4;
}



ulong FUN_7101508f50(long *param_1,long *param_2)

{
  int iVar1;
  long lVar2;
  uint uVar3;
  ulong uVar4;
  byte *pbVar5;
  long alStack_e0 [6];
  byte *local_b0;
  int local_a8;
  byte local_a4 [127];
  undefined1 local_25;
  
  (**(code **)(*param_2 + 0x10))(alStack_e0);
  local_25 = 0;
  local_b0 = local_a4;
  local_a8 = 0x80;
  local_a4[0] = 0;
  uVar3 = FUN_71015093d0((long *)&local_b0,0x71030d8a75,alStack_e0);
  uVar4 = (ulong)uVar3;
  *(undefined4 *)(param_1 + 1) = 0x80;
  *param_1 = (long)param_1 + 0xc;
  *(undefined1 *)((long)param_1 + 0x8b) = 0;
  local_b0[(long)local_a8 + -1] = 0;
  pbVar5 = (byte *)*param_1;
  if (pbVar5 != local_b0) {
    if (local_b0 == (byte *)0x0) {
LAB_7101509008:
      uVar4 = 0;
    }
    else {
      uVar4 = (ulong)*local_b0;
      if (*local_b0 != 0) {
        uVar4 = 0;
        do {
          if (uVar4 == 0x400000) goto LAB_7101509008;
          if (local_b0[uVar4 + 1] == 0) {
            uVar4 = uVar4 + 1;
            break;
          }
          lVar2 = uVar4 + 2;
          uVar4 = uVar4 + 2;
        } while (local_b0[lVar2] != 0);
      }
    }
    iVar1 = (int)uVar4;
    if ((int)param_1[1] <= (int)uVar4) {
      iVar1 = (int)param_1[1] + -1;
    }
    uVar4 = thunk_EXT_FUN_02e95df0(pbVar5,local_b0,(long)iVar1);
    pbVar5[iVar1] = 0;
  }
  return uVar4;
}



void FUN_7101509368(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015093a8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



int FUN_71015093d0(long *param_1,long param_2,long *param_3)

{
  int iVar1;
  long lVar2;
  undefined4 uVar3;
  ulong uVar4;
  long lVar5;
  char *pcVar6;
  int iVar7;
  long lVar8;
  long local_90;
  long *local_88;
  undefined8 local_80;
  undefined1 local_78;
  long local_70;
  undefined1 **ppuStack_68;
  int local_60;
  undefined1 *local_58;
  int local_50;
  int iStack_44;
  undefined1 auStack_40 [32];
  
  lVar5 = *param_1;
  *(undefined1 *)((int)param_1[1] + lVar5 + -1) = 0;
  pcVar6 = (char *)*param_1;
  if ((pcVar6 == (char *)0x0) || (*pcVar6 == '\0')) {
LAB_7101509434:
    lVar8 = 0;
  }
  else {
    lVar8 = 0;
    do {
      if (lVar8 == 0x400000) goto LAB_7101509434;
      if (pcVar6[lVar8 + 1] == '\0') {
        lVar8 = lVar8 + 1;
        break;
      }
      lVar2 = lVar8 + 2;
      lVar8 = lVar8 + 2;
    } while (pcVar6[lVar2] != '\0');
  }
  iVar7 = (int)lVar8;
  iVar1 = (int)param_1[1] - iVar7;
  if (iVar1 == 0 || (int)param_1[1] < iVar7) {
    local_58 = (undefined1 *)0x0;
  }
  else {
    local_58 = (undefined1 *)(lVar5 + iVar7);
  }
  local_50 = 0;
  if (local_58 != (undefined1 *)0x0) {
    local_50 = iVar1;
  }
  local_88 = &local_70;
  local_58[(long)local_50 + -1] = 0;
  local_80 = 0;
  local_78 = 0;
  local_90 = param_2;
  if (param_2 != 0) {
    uVar3 = thunk_EXT_FUN_02e95df0(param_2);
    local_80 = CONCAT44(uVar3,(int)local_80);
  }
  ppuStack_68 = &local_58;
  local_60 = 0;
  local_70 = DAT_7103a71198 + 0x10;
  *local_58 = 0;
  uVar4 = FUN_71024fd620(&local_90,auStack_40,&iStack_44);
  if ((uVar4 & 1) != 0) {
    *(undefined1 *)((long)(int)param_3[1] + *param_3 + -1) = 0;
    lVar5 = *param_3;
    *(undefined1 *)((int)param_3[1] + lVar5 + -1) = 0;
    pcVar6 = (char *)*param_3;
    if ((pcVar6 == (char *)0x0) || (*pcVar6 == '\0')) {
LAB_7101509514:
      lVar8 = 0;
    }
    else {
      lVar8 = 0;
      do {
        if (lVar8 == 0x400000) goto LAB_7101509514;
        if (pcVar6[lVar8 + 1] == '\0') {
          lVar8 = lVar8 + 1;
          break;
        }
        lVar2 = lVar8 + 2;
        lVar8 = lVar8 + 2;
      } while (pcVar6[lVar2] != '\0');
    }
    (**(code **)(*local_88 + 0x10))(local_88,lVar5,lVar8);
  }
  if (local_90 != 0) {
    local_78 = 0;
    while( true ) {
      if (local_80._4_4_ <= (int)local_80) break;
      FUN_71024fd620(&local_90,auStack_40,&iStack_44);
    }
  }
  return local_60 + iVar7;
}



char * FUN_7101509730(long param_1)

{
  uint uVar1;
  short sVar2;
  uint uVar3;
  short *psVar4;
  char *pcVar5;
  long lVar6;
  undefined1 auVar7 [16];
  
  if (*(int *)(param_1 + 0x18) == 1) {
    auVar7 = FUN_7102813520((undefined8 *)(param_1 + 8),"ModelNameIn");
    psVar4 = auVar7._0_8_;
    if ((auVar7._8_8_ & 0xff00000000) == 0xa000000000) {
      sVar2 = *psVar4;
      uVar1 = *(uint *)(psVar4 + 4);
      uVar3 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
      uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
      if (sVar2 != 0x5942) {
        uVar3 = uVar1;
      }
      if (uVar3 != 0) {
        pcVar5 = (char *)((long)psVar4 + (long)(int)uVar3);
        if (*pcVar5 == -0x3b) {
          uVar1 = *(uint *)(pcVar5 + 4);
          uVar3 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
          uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
          if (sVar2 != 0x5942) {
            uVar3 = uVar1;
          }
          lVar6 = *(long *)(pcVar5 + uVar3);
        }
        else {
          lVar6 = 0;
        }
        uVar1 = *(uint *)(pcVar5 + ((long)(auVar7._8_8_ << 0x20) >> 0x1e) + 4);
        uVar3 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
        uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
        if (sVar2 != 0x5942) {
          uVar3 = uVar1;
        }
        if (pcVar5[(ulong)uVar3 + lVar6] != '\0') {
          pcVar5 = "ModelNameIn";
          goto LAB_7101509810;
        }
      }
    }
  }
  pcVar5 = "ModelName";
LAB_7101509810:
  auVar7 = FUN_7102813520((undefined8 *)(param_1 + 8),pcVar5);
  psVar4 = auVar7._0_8_;
  if ((auVar7._8_8_ & 0xff00000000) == 0xa000000000) {
    sVar2 = *psVar4;
    uVar1 = *(uint *)(psVar4 + 4);
    uVar3 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
    uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
    if (sVar2 != 0x5942) {
      uVar3 = uVar1;
    }
    if (uVar3 != 0) {
      pcVar5 = (char *)((long)psVar4 + (long)(int)uVar3);
      if (*pcVar5 == -0x3b) {
        uVar1 = *(uint *)(pcVar5 + 4);
        uVar3 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
        uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
        if (sVar2 != 0x5942) {
          uVar3 = uVar1;
        }
        lVar6 = *(long *)(pcVar5 + uVar3);
      }
      else {
        lVar6 = 0;
      }
      uVar1 = *(uint *)(pcVar5 + ((long)(auVar7._8_8_ << 0x20) >> 0x1e) + 4);
      uVar3 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
      uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
      if (sVar2 != 0x5942) {
        uVar3 = uVar1;
      }
      return pcVar5 + (ulong)uVar3 + lVar6;
    }
  }
  return "";
}



undefined8 FUN_710150aeb0(long param_1,long param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  long lVar5;
  
  if ((param_3 != 0) && (uVar1 = *(uint *)(param_1 + 0x34), uVar1 != 0)) {
    uVar3 = 0;
    if (uVar1 != 0) {
      uVar3 = param_3 / uVar1;
    }
    uVar3 = param_3 - uVar3 * uVar1;
    uVar4 = uVar3;
    do {
      uVar2 = *(uint *)(*(long *)(param_1 + 0x28) +
                       (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
      if (uVar2 == param_3) {
        lVar5 = *(long *)(*(long *)(param_1 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
        if (lVar5 == 0) {
          return 0;
        }
        *(long *)(param_2 + 8) = lVar5;
        return 1;
      }
      if (uVar2 == 0) {
        return 0;
      }
      uVar2 = 0;
      if ((int)(uVar4 + 1) < (int)uVar1) {
        uVar2 = uVar4 + 1;
      }
      uVar4 = uVar2;
    } while (uVar2 != uVar3);
  }
  return 0;
}



void FUN_710150af20(undefined8 param_1,long *param_2,undefined8 *param_3)

{
  int iVar1;
  char cVar2;
  long lVar3;
  byte *pbVar4;
  char *pcVar5;
  ulong uVar6;
  ulong uVar7;
  char *pcVar8;
  byte *pbVar9;
  
  pcVar5 = (char *)*param_3;
  if (pcVar5 == (char *)0x0) {
    uVar6 = 0;
  }
  else if (*pcVar5 == '\0') {
    uVar6 = 0;
  }
  else {
    uVar6 = 0;
    do {
      if (uVar6 == 0x400000) {
        uVar6 = 0;
        goto LAB_710150af94;
      }
      if (pcVar5[uVar6 + 1] == '\0') {
        uVar6 = uVar6 + 1;
        break;
      }
      lVar3 = uVar6 + 2;
      uVar6 = uVar6 + 2;
    } while (pcVar5[lVar3] != '\0');
    uVar6 = uVar6 & 0xffffffff;
  }
LAB_710150af94:
  do {
    uVar7 = uVar6;
    uVar6 = uVar7 - 1;
    if ((long)uVar7 < 1) goto LAB_710150aff4;
  } while (pcVar5[uVar6 & 0xffffffff] != '/');
  if ((uint)uVar7 < 0x400001) {
    if ((int)uVar6 == -1) {
LAB_710150aff4:
      uVar7 = 0;
    }
    else {
      uVar7 = uVar7 & 0xffffffff;
      uVar6 = (ulong)((int)uVar6 + 1);
      pcVar8 = pcVar5;
      do {
        pbVar4 = DAT_7103a59fe0;
        if (*pcVar8 == '\0') goto LAB_710150affc;
        uVar6 = uVar6 - 1;
        pcVar8 = pcVar8 + 1;
      } while (uVar6 != 0);
    }
    pbVar4 = (byte *)(pcVar5 + uVar7);
  }
  else {
    pbVar4 = &DAT_71032a8da0;
  }
LAB_710150affc:
  pbVar9 = (byte *)*param_2;
  if (pbVar9 != pbVar4) {
    if (pbVar4 == (byte *)0x0) {
LAB_710150b044:
      uVar6 = 0;
    }
    else {
      uVar6 = (ulong)*pbVar4;
      if (*pbVar4 != 0) {
        uVar6 = 0;
        do {
          if (uVar6 == 0x400000) goto LAB_710150b044;
          if (pbVar4[uVar6 + 1] == 0) {
            uVar6 = uVar6 + 1;
            break;
          }
          lVar3 = uVar6 + 2;
          uVar6 = uVar6 + 2;
        } while (pbVar4[lVar3] != 0);
      }
    }
    iVar1 = (int)uVar6;
    if ((int)param_2[1] <= (int)uVar6) {
      iVar1 = (int)param_2[1] + -1;
    }
    thunk_EXT_FUN_02e95df0(pbVar9,pbVar4,(long)iVar1);
    pbVar9[iVar1] = 0;
    pbVar4 = (byte *)*param_2;
  }
  uVar6 = 0;
  pbVar4[(long)(int)param_2[1] + -1] = 0;
  while( true ) {
    cVar2 = *(char *)(*param_2 + uVar6);
    if (cVar2 == '\0') {
      return;
    }
    if (cVar2 == '.') break;
    uVar6 = uVar6 + 1;
    if ((int)uVar6 == 0x400001) {
      return;
    }
  }
  if ((int)uVar6 < 0) {
    return;
  }
  uVar7 = uVar6 & 0xffffffff;
  if ((int)param_2[1] <= (int)uVar6) {
    uVar7 = (long)(int)param_2[1] - 1;
  }
  *(undefined1 *)(*param_2 + uVar7) = 0;
  return;
}



uint FUN_710150b0e0(long param_1,undefined8 *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  byte *local_130;
  int local_128;
  byte local_124 [255];
  undefined1 local_25;
  
  local_25 = 0;
  local_130 = local_124;
  local_124[0] = 0;
  local_128 = 0x100;
  FUN_710150af20(param_1,(long *)&local_130,param_2);
  local_130[(long)local_128 + -1] = 0;
  if (((*local_130 != 0) && (uVar5 = FUN_7100bb2120(local_130,0), uVar5 != 0)) &&
     (uVar1 = *(uint *)(param_1 + 0x34), uVar1 != 0)) {
    uVar3 = 0;
    if (uVar1 != 0) {
      uVar3 = uVar5 / uVar1;
    }
    uVar3 = uVar5 - uVar3 * uVar1;
    uVar4 = uVar3;
    do {
      uVar2 = *(uint *)(*(long *)(param_1 + 0x28) +
                       (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
      if (uVar2 == uVar5) {
        if (*(long *)(*(long *)(param_1 + 0x28) + (long)(int)uVar4 * 0x10 + 8) == 0) {
          return 0;
        }
        return uVar5;
      }
      if (uVar2 == 0) {
        return 0;
      }
      uVar2 = 0;
      if ((int)(uVar4 + 1) < (int)uVar1) {
        uVar2 = uVar4 + 1;
      }
      uVar4 = uVar2;
    } while (uVar2 != uVar3);
  }
  return 0;
}



undefined4 FUN_710150b1b0(long param_1,uint param_2,uint param_3)

{
  long *plVar1;
  int *piVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  bool bVar8;
  long lVar9;
  long lVar10;
  uint uVar11;
  long *plVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  float fVar16;
  undefined4 local_94;
  undefined *local_90;
  long local_88;
  
  if (param_2 != 0xffffffff) {
    thunk_EXT_FUN_02e95df0();
    piVar2 = (int *)(param_1 + 0x88) + (ulong)param_2 * 4;
    if (7 < param_2) {
      piVar2 = (int *)(param_1 + 0x88);
    }
    if (*piVar2 != 0) {
      plVar12 = *(long **)(piVar2 + 2);
      local_94 = 0;
      fVar16 = 0.0;
      plVar1 = plVar12 + *piVar2;
      uVar15 = (param_3 ^ param_3 >> 0x1e) * 0x6c078965 + 1;
      uVar11 = (uVar15 ^ uVar15 >> 0x1e) * 0x6c078965 + 2;
      uVar14 = (uVar11 ^ uVar11 >> 0x1e) * 0x6c078965 + 3;
      uVar13 = (uVar14 ^ uVar14 >> 0x1e) * 0x6c078965 + 4;
      do {
        lVar10 = *plVar12;
        local_90 = &DAT_7103959c90;
        local_88 = 0;
        uVar3 = *(uint *)(lVar10 + 0x50);
        if ((uVar3 != 0) && (uVar4 = *(uint *)(param_1 + 0x34), uVar4 != 0)) {
          uVar6 = 0;
          if (uVar4 != 0) {
            uVar6 = uVar3 / uVar4;
          }
          uVar6 = uVar3 - uVar6 * uVar4;
          uVar7 = uVar6;
          do {
            uVar5 = *(uint *)(*(long *)(param_1 + 0x28) +
                             (-(ulong)(uVar7 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar7 << 4));
            if (uVar5 == uVar3) {
              lVar9 = *(long *)(*(long *)(param_1 + 0x28) + (long)(int)uVar7 * 0x10 + 8);
              if (lVar9 != 0) {
                local_88 = lVar9;
              }
              break;
            }
            if (uVar5 == 0) break;
            uVar5 = 0;
            if ((int)(uVar7 + 1) < (int)uVar4) {
              uVar5 = uVar7 + 1;
            }
            uVar7 = uVar5;
          } while (uVar5 != uVar6);
        }
        if ((((-1 < *(int *)(lVar10 + 0x58)) && (bVar8 = FUN_7101508cdc((long)&local_90), bVar8)) &&
            (fVar16 = fVar16 + 1.0, ABS(fVar16) != INFINITY)) &&
           ((fVar16 < 0.0 ||
            (uVar15 = uVar15 ^ uVar15 << 0xb, uVar3 = uVar13 >> 0x13 ^ uVar15 >> 8 ^ uVar13 ^ uVar15
            , uVar15 = uVar11, uVar11 = uVar14, uVar14 = uVar13, uVar13 = uVar3,
            fVar16 * ((float)(uVar3 >> 9 | 0x3f800000) + -1.0) + 0.0 < 1.0)))) {
          local_94 = *(undefined4 *)(lVar10 + 0x50);
        }
        plVar12 = plVar12 + 1;
        if (plVar12 == plVar1) {
          return local_94;
        }
      } while( true );
    }
  }
  return 0;
}



bool FUN_710150b3c0(long param_1,uint *param_2,uint *param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  long lVar7;
  long *plVar8;
  undefined *local_30;
  long local_28;
  
  if ((param_4 & 1) == 0) {
    return false;
  }
  uVar6 = *param_2;
  if (uVar6 == 0) {
    return false;
  }
  uVar1 = *param_3;
  if (uVar1 == 0) {
    return false;
  }
  local_30 = &DAT_7103959c90;
  uVar2 = *(uint *)(param_1 + 0x34);
  if (uVar2 == 0) {
    return false;
  }
  uVar5 = 0;
  if (uVar2 != 0) {
    uVar5 = uVar6 / uVar2;
  }
  lVar7 = *(long *)(param_1 + 0x28);
  uVar5 = uVar6 - uVar5 * uVar2;
  uVar4 = uVar5;
  do {
    uVar3 = *(uint *)(lVar7 + (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
    if (uVar3 == uVar6) {
      local_28 = *(long *)(lVar7 + (long)(int)uVar4 * 0x10 + 8);
      if (local_28 == 0) {
        return false;
      }
      uVar6 = 0;
      if (uVar2 != 0) {
        uVar6 = uVar1 / uVar2;
      }
      uVar6 = uVar1 - uVar6 * uVar2;
      uVar5 = uVar6;
      do {
        uVar4 = *(uint *)(lVar7 + (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4)
                         );
        if (uVar4 == uVar1) {
          plVar8 = *(long **)(lVar7 + (long)(int)uVar5 * 0x10 + 8);
          if (plVar8 == (long *)0x0) {
            return false;
          }
          uVar6 = FUN_7101508548((long)&local_30,1);
          if ((uVar6 & 1) == 0) {
            return false;
          }
          *(undefined1 *)((long)(int)plVar8[1] + *plVar8 + -1) = 0;
          return *(char *)*plVar8 != '\0';
        }
        if (uVar4 == 0) {
          return false;
        }
        uVar4 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar4 = uVar5 + 1;
        }
        uVar5 = uVar4;
      } while (uVar4 != uVar6);
      return false;
    }
    if (uVar3 == 0) {
      return false;
    }
    uVar3 = 0;
    if ((int)(uVar4 + 1) < (int)uVar2) {
      uVar3 = uVar4 + 1;
    }
    uVar4 = uVar3;
  } while (uVar3 != uVar5);
  return false;
}



undefined8 FUN_710150b4e4(long *param_1,long param_2,undefined4 param_3)

{
  char *pcVar1;
  uint uVar2;
  short sVar3;
  short *psVar4;
  char cVar5;
  uint uVar6;
  undefined8 uVar7;
  undefined4 uVar8;
  long lVar9;
  undefined8 uVar10;
  long lVar11;
  long lVar12;
  undefined8 *puVar13;
  char *pcVar14;
  undefined1 auVar15 [16];
  undefined8 local_78;
  undefined4 local_70;
  undefined1 local_6c;
  long local_68;
  undefined8 local_60;
  undefined4 local_58;
  undefined1 local_54;
  
  *(undefined1 *)((long)(int)param_1[1] + *param_1 + -1) = 0;
  lVar12 = DAT_7103a61970;
  if ((*(char *)*param_1 != '\0') && (uVar6 = *(uint *)((long)param_1 + 100), -1 < (int)uVar6)) {
    lVar9 = 0x460;
    if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1d) {
      lVar9 = 0;
    }
    lVar9 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar9 + 0x20);
    if (*(uint *)(lVar9 + 0x20) <= uVar6) {
      uVar6 = 0;
    }
    local_58 = 0;
    lVar9 = *(long *)(lVar9 + 0x28) + (ulong)uVar6 * 0x48;
    local_54 = 0;
    local_68 = DAT_7103a61970 + 0x10;
    pcVar14 = (char *)(lVar9 + 0x24);
    puVar13 = (undefined8 *)(lVar9 + 0x18);
    local_60._0_5_ = 0;
    local_60._5_3_ = 0;
    if ((*pcVar14 == -0x3c) || (*pcVar14 == -0x3f)) {
      local_60._0_5_ = (undefined5)*puVar13;
      uVar7 = *(undefined8 *)(lVar9 + 0x1d);
      local_60._5_3_ = (undefined3)uVar7;
      local_58 = (undefined4)((ulong)uVar7 >> 0x18);
      local_54 = (undefined1)((ulong)uVar7 >> 0x38);
    }
    auVar15 = FUN_7102813520(&local_60,"ModelName");
    psVar4 = auVar15._0_8_;
    if ((auVar15._8_8_ & 0xff00000000) == 0xa000000000) {
      sVar3 = *psVar4;
      uVar2 = *(uint *)(psVar4 + 4);
      uVar6 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
      uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
      if (sVar3 != 0x5942) {
        uVar6 = uVar2;
      }
      if (uVar6 == 0) goto LAB_710150b660;
      pcVar1 = (char *)((long)psVar4 + (long)(int)uVar6);
      if (*pcVar1 == -0x3b) {
        uVar2 = *(uint *)(pcVar1 + 4);
        uVar6 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
        uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
        if (sVar3 != 0x5942) {
          uVar6 = uVar2;
        }
        lVar11 = *(long *)(pcVar1 + uVar6);
      }
      else {
        lVar11 = 0;
      }
      uVar2 = *(uint *)(pcVar1 + ((long)(auVar15._8_8_ << 0x20) >> 0x1e) + 4);
      uVar6 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
      uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
      if (sVar3 != 0x5942) {
        uVar6 = uVar2;
      }
      if (pcVar1[(ulong)uVar6 + lVar11] == '\0') goto LAB_710150b660;
LAB_710150b738:
      uVar7 = 0;
      switch(param_3) {
      case 0:
        if (*(int *)((long)param_1 + 0x54) != 3) goto switchD_710150b75c_default;
        break;
      case 1:
        local_58 = 0;
        local_68 = lVar12 + 0x10;
        local_54 = 0;
        local_60._0_5_ = 0;
        local_60._5_3_ = 0;
        if ((*pcVar14 == -0x3c) || (*pcVar14 == -0x3f)) {
          local_60._0_5_ = (undefined5)*puVar13;
          uVar7 = *(undefined8 *)(lVar9 + 0x1d);
          local_60._5_3_ = (undefined3)uVar7;
          local_58 = (undefined4)((ulong)uVar7 >> 0x18);
          local_54 = (undefined1)((ulong)uVar7 >> 0x38);
        }
        auVar15 = FUN_7102813520(&local_60,"ModelNameIn");
        psVar4 = auVar15._0_8_;
        if ((auVar15._8_8_ & 0xff00000000) == 0xa000000000) {
          sVar3 = *psVar4;
          uVar2 = *(uint *)(psVar4 + 4);
          uVar6 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
          uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
          if (sVar3 != 0x5942) {
            uVar6 = uVar2;
          }
          if (uVar6 != 0) {
            pcVar1 = (char *)((long)psVar4 + (long)(int)uVar6);
            if (*pcVar1 == -0x3b) {
              uVar2 = *(uint *)(pcVar1 + 4);
              uVar6 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
              uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
              if (sVar3 != 0x5942) {
                uVar6 = uVar2;
              }
              lVar12 = *(long *)(pcVar1 + uVar6);
            }
            else {
              lVar12 = 0;
            }
            uVar2 = *(uint *)(pcVar1 + ((long)(auVar15._8_8_ << 0x20) >> 0x1e) + 4);
            uVar6 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
            uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
            if (sVar3 != 0x5942) {
              uVar6 = uVar2;
            }
            if (pcVar1[(ulong)uVar6 + lVar12] != '\0') goto switchD_710150b75c_default;
          }
        }
        break;
      case 2:
        goto switchD_710150b75c_caseD_2;
      case 3:
      case 4:
        if (*(int *)((long)param_1 + 0x54) == 3) goto switchD_710150b75c_default;
        break;
      default:
switchD_710150b75c_default:
        cVar5 = *pcVar14;
        if ((cVar5 == -0x3c) || (cVar5 == -0x3f)) {
          uVar10 = *puVar13;
          uVar8 = *(undefined4 *)(lVar9 + 0x20);
        }
        else {
          cVar5 = '\0';
          uVar8 = 0;
          uVar10 = 0;
        }
        uVar7 = 1;
        *(undefined8 *)(param_2 + 8) = uVar10;
        *(undefined4 *)(param_2 + 0x10) = uVar8;
        *(char *)(param_2 + 0x14) = cVar5;
        *(undefined4 *)(param_2 + 0x18) = param_3;
        goto switchD_710150b75c_caseD_2;
      }
    }
    else {
LAB_710150b660:
      local_70 = 0;
      local_6c = 0;
      local_78._0_5_ = 0;
      local_78._5_3_ = 0;
      if ((*pcVar14 == -0x3c) || (*pcVar14 == -0x3f)) {
        local_78._0_5_ = (undefined5)*puVar13;
        uVar7 = *(undefined8 *)(lVar9 + 0x1d);
        local_78._5_3_ = (undefined3)uVar7;
        local_70 = (undefined4)((ulong)uVar7 >> 0x18);
        local_6c = (undefined1)((ulong)uVar7 >> 0x38);
      }
      auVar15 = FUN_7102813520(&local_78,"TextureProjectName");
      psVar4 = auVar15._0_8_;
      if ((auVar15._8_8_ & 0xff00000000) == 0xa000000000) {
        sVar3 = *psVar4;
        uVar2 = *(uint *)(psVar4 + 4);
        uVar6 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
        uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
        if (sVar3 != 0x5942) {
          uVar6 = uVar2;
        }
        if (uVar6 != 0) {
          pcVar1 = (char *)((long)psVar4 + (long)(int)uVar6);
          if (*pcVar1 == -0x3b) {
            uVar2 = *(uint *)(pcVar1 + 4);
            uVar6 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
            uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
            if (sVar3 != 0x5942) {
              uVar6 = uVar2;
            }
            lVar11 = *(long *)(pcVar1 + uVar6);
          }
          else {
            lVar11 = 0;
          }
          uVar2 = *(uint *)(pcVar1 + ((long)(auVar15._8_8_ << 0x20) >> 0x1e) + 4);
          uVar6 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
          uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
          if (sVar3 != 0x5942) {
            uVar6 = uVar2;
          }
          if (pcVar1[(ulong)uVar6 + lVar11] != '\0') goto LAB_710150b738;
        }
      }
    }
  }
  uVar7 = 0;
switchD_710150b75c_caseD_2:
  return uVar7;
}



uint FUN_710150b8c0(long param_1,uint param_2)

{
  uint uVar1;
  ulong uVar2;
  uint uVar3;
  long lVar4;
  short *psVar5;
  undefined1 auVar6 [16];
  long local_48;
  undefined4 local_40;
  undefined1 local_3c;
  undefined1 local_38 [16];
  undefined8 local_28;
  undefined5 uStack_20;
  undefined3 uStack_1b;
  uint local_14;
  
  uVar3 = *(uint *)(param_1 + 100);
  if (-1 < (int)uVar3) {
    lVar4 = 0x460;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1d) {
      lVar4 = 0;
    }
    lVar4 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar4 + 0x20);
    if (*(uint *)(lVar4 + 0x20) <= uVar3) {
      uVar3 = 0;
    }
    lVar4 = *(long *)(lVar4 + 0x28) + (ulong)uVar3 * 0x48;
    if ((*(byte *)(lVar4 + 0x14) & 0xf7) == 0xc0) {
      psVar5 = *(short **)(lVar4 + 8);
      uVar1 = *(uint *)((long)psVar5 + (ulong)*(uint *)(lVar4 + 0x10));
      uVar3 = uVar1 >> 8;
      if (*psVar5 == 0x5942) {
        uVar3 = uVar3 & 0xff00 | uVar1 >> 0x18 | (uVar3 & 0xff) << 0x10;
        if (uVar3 == 0) {
          return 0;
        }
      }
      else if (uVar1 < 0x100) {
        return 0;
      }
      if (param_2 < uVar3) {
        local_40 = 0;
        local_48 = 0;
        local_3c = 0;
        local_28._0_5_ = (undefined5)*(undefined8 *)(lVar4 + 8);
        local_28._5_3_ = (undefined3)*(undefined8 *)(lVar4 + 0xd);
        uStack_20 = (undefined5)((ulong)*(undefined8 *)(lVar4 + 0xd) >> 0x18);
        auVar6 = FUN_71028132dc(&local_28,param_2);
        local_14 = 0;
        if (auVar6._0_8_ != 0) {
          uVar3 = auVar6._12_4_ & 0xff;
          if ((uVar3 == 0xc4) || (uVar3 == 0xc1)) {
            local_40 = auVar6._8_4_;
            local_3c = auVar6[0xc];
            local_48 = auVar6._0_8_;
          }
          uVar3 = auVar6._12_4_ & 0xff;
          if ((uVar3 == 0xc4) || (uVar3 == 0xc1)) {
            local_14 = 0;
            local_28._0_5_ = 0x7103954ef0;
            local_28._5_3_ = 0;
            uStack_20 = SUB85(&local_14,0);
            uStack_1b = (undefined3)((ulong)&local_14 >> 0x28);
            local_38 = FUN_7102813520(&local_48,"Color");
            uVar2 = FUN_7101498f30((long)&local_28,(undefined8 *)local_38);
            if ((uVar2 & 1) == 0) {
              local_14 = 0;
            }
          }
          else {
            local_14 = 0;
          }
        }
        return local_14;
      }
    }
  }
  return 0;
}



ulong FUN_710150ba44(long param_1,int param_2,uint param_3)

{
  uint uVar1;
  int iVar2;
  ulong uVar3;
  uint uVar4;
  long lVar5;
  short *psVar6;
  undefined1 auVar7 [16];
  undefined8 local_48;
  undefined5 uStack_40;
  undefined *local_38;
  long local_30;
  undefined4 local_28;
  undefined1 local_24;
  
  uVar4 = *(uint *)(param_1 + 100);
  if ((int)uVar4 < 0) {
    return 0;
  }
  lVar5 = 0x460;
  if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1d) {
    lVar5 = 0;
  }
  lVar5 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar5 + 0x20);
  if (*(uint *)(lVar5 + 0x20) <= uVar4) {
    uVar4 = 0;
  }
  lVar5 = *(long *)(lVar5 + 0x28) + (ulong)uVar4 * 0x48;
  if ((*(byte *)(lVar5 + 0x14) & 0xf7) == 0xc0) {
    psVar6 = *(short **)(lVar5 + 8);
    uVar1 = *(uint *)((long)psVar6 + (ulong)*(uint *)(lVar5 + 0x10));
    uVar4 = uVar1 >> 8;
    if (*psVar6 == 0x5942) {
      uVar4 = uVar4 & 0xff00 | uVar1 >> 0x18 | (uVar4 & 0xff) << 0x10;
      if (uVar4 == 0) {
        return 0;
      }
    }
    else if (uVar1 < 0x100) {
      return 0;
    }
    if (param_3 < uVar4) {
      local_28 = 0;
      local_38 = &DAT_7103959d60;
      local_30 = 0;
      local_24 = 0;
      local_48._0_5_ = (undefined5)*(undefined8 *)(lVar5 + 8);
      local_48._5_3_ = (undefined3)*(undefined8 *)(lVar5 + 0xd);
      uStack_40 = (undefined5)((ulong)*(undefined8 *)(lVar5 + 0xd) >> 0x18);
      auVar7 = FUN_71028132dc(&local_48,param_3);
      if (auVar7._0_8_ == 0) {
        return 0;
      }
      uVar4 = auVar7._12_4_ & 0xff;
      if ((uVar4 == 0xc4) || (uVar4 == 0xc1)) {
        local_28 = auVar7._8_4_;
        local_24 = auVar7[0xc];
        local_30 = auVar7._0_8_;
      }
      uVar4 = auVar7._12_4_ & 0xff;
      if ((uVar4 == 0xc4) || (uVar4 == 0xc1)) {
        if (param_2 == 0) {
          auVar7 = FUN_7102813520(&local_30,"SubAccessoryColorIndex0");
          uVar4 = auVar7._12_4_ & 0xff;
          iVar2 = auVar7._8_4_;
          if (uVar4 == 0xd3) {
            return auVar7._8_8_ & 0xffffffff;
          }
          if (uVar4 != 0xd1) {
            return 0;
          }
          uVar3 = auVar7._8_8_ & 0xffffffff;
        }
        else {
          if (param_2 != 1) {
            return 0;
          }
          auVar7 = FUN_7102813520(&local_30,"SubAccessoryColorIndex1");
          uVar3 = auVar7._8_8_;
          uVar4 = auVar7._12_4_ & 0xff;
          if (uVar4 == 0xd3) {
            return uVar3;
          }
          if (uVar4 != 0xd1) {
            return 0;
          }
          iVar2 = auVar7._8_4_;
        }
        if (-1 < iVar2) {
          return uVar3;
        }
      }
    }
  }
  return 0;
}



long FUN_710150bbfc(long *param_1)

{
  uint uVar1;
  long lVar2;
  
  *(undefined1 *)((long)(int)param_1[1] + *param_1 + -1) = 0;
  if ((*(char *)*param_1 != '\0') && (uVar1 = *(uint *)(param_1 + 0xc), -1 < (int)uVar1)) {
    lVar2 = 0x438;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1c) {
      lVar2 = 0;
    }
    lVar2 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar2 + 0x20);
    if (*(uint *)(lVar2 + 0x20) <= uVar1) {
      uVar1 = 0;
    }
    return *(long *)(lVar2 + 0x28) + (ulong)uVar1 * 0x24;
  }
  return 0;
}



undefined4 FUN_710150bc7c(long param_1)

{
  uint uVar1;
  long lVar2;
  
  uVar1 = *(uint *)(param_1 + 100);
  if (-1 < (int)uVar1) {
    lVar2 = 0x460;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1d) {
      lVar2 = 0;
    }
    lVar2 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar2 + 0x20);
    if (*(uint *)(lVar2 + 0x20) <= uVar1) {
      uVar1 = 0;
    }
    return *(undefined4 *)(*(long *)(lVar2 + 0x28) + (ulong)uVar1 * 0x48 + 0x30);
  }
  return 0xffffffff;
}



bool FUN_710150bcdc(long param_1)

{
  uint uVar1;
  long lVar2;
  
  uVar1 = *(uint *)(param_1 + 100);
  if (-1 < (int)uVar1) {
    lVar2 = 0x460;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1d) {
      lVar2 = 0;
    }
    lVar2 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar2 + 0x20);
    if (*(uint *)(lVar2 + 0x20) <= uVar1) {
      uVar1 = 0;
    }
    return *(char *)(*(long *)(lVar2 + 0x28) + (ulong)uVar1 * 0x48 + 0x41) != '\0';
  }
  return false;
}



undefined8 FUN_710150bd44(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a61988 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar1 != 0))
  {
    *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61988);
  }
  if (param_2 != DAT_7103a61980) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_710150be44(void)

{
  int iVar1;
  
  if (((*DAT_7103a61988 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar1 != 0))
  {
    *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61988);
  }
  return DAT_7103a61980;
}



void FUN_710150bea4(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710150bee4. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_710150bf04(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710150bf44. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_710150bf70(undefined8 *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined8 *puVar7;
  long lVar8;
  
  *param_1 = &DAT_7103959e00;
  param_1[1] = 0;
  if ((*param_2 != 0) &&
     (puVar7 = *(undefined8 **)(*DAT_7103a59ec8 + 0x30), puVar7 != (undefined8 *)0x0)) {
    if (((*DAT_7103a619a8 & 1) == 0) && (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a619a8), iVar6 != 0)
       ) {
      *DAT_7103a619a0 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a619a8);
    }
    lVar8 = (**(code **)*puVar7)(puVar7,DAT_7103a619a0);
    if (((lVar8 != 0) && (uVar1 = *param_2, uVar1 != 0)) &&
       (uVar2 = *(uint *)(lVar8 + 0x44), uVar2 != 0)) {
      uVar4 = 0;
      if (uVar2 != 0) {
        uVar4 = uVar1 / uVar2;
      }
      uVar4 = uVar1 - uVar4 * uVar2;
      uVar5 = uVar4;
      do {
        uVar3 = *(uint *)(*(long *)(lVar8 + 0x38) +
                         (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
        if (uVar3 == uVar1) {
          lVar8 = *(long *)(*(long *)(lVar8 + 0x38) + (long)(int)uVar5 * 0x10 + 8);
          if (lVar8 == 0) {
            return;
          }
          param_1[1] = lVar8;
          return;
        }
        if (uVar3 == 0) {
          return;
        }
        uVar3 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar3 = uVar5 + 1;
        }
        uVar5 = uVar3;
      } while (uVar3 != uVar4);
    }
  }
  return;
}



void FUN_710150c0a0(undefined8 *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  long *plVar6;
  byte *pbVar7;
  int iVar8;
  undefined8 *puVar9;
  long lVar10;
  uint *puVar11;
  
  pbVar7 = DAT_7103a619a8;
  plVar6 = DAT_7103a59ec8;
  puVar9 = *(undefined8 **)(*DAT_7103a59ec8 + 0x30);
  lVar10 = 0;
  if (puVar9 != (undefined8 *)0x0) {
    if (((*DAT_7103a619a8 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(DAT_7103a619a8), iVar8 != 0)
       ) {
      *DAT_7103a619a0 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a619a8);
    }
    lVar10 = (**(code **)*puVar9)(puVar9,DAT_7103a619a0);
  }
  puVar11 = DAT_7103a5d0a0;
  if ((-1 < (int)param_2) && ((int)param_2 < *(int *)(lVar10 + 0x18))) {
    puVar11 = (uint *)(*(long *)(*(long *)(lVar10 + 0x20) + (ulong)param_2 * 8) + 0x10);
  }
  *param_1 = &DAT_7103959e00;
  param_1[1] = 0;
  if ((*puVar11 != 0) && (puVar9 = *(undefined8 **)(*plVar6 + 0x30), puVar9 != (undefined8 *)0x0)) {
    if (((*pbVar7 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(DAT_7103a619a8), iVar8 != 0)) {
      *DAT_7103a619a0 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a619a8);
    }
    lVar10 = (**(code **)*puVar9)(puVar9,DAT_7103a619a0);
    if (((lVar10 != 0) && (uVar1 = *puVar11, uVar1 != 0)) &&
       (uVar2 = *(uint *)(lVar10 + 0x44), uVar2 != 0)) {
      uVar4 = 0;
      if (uVar2 != 0) {
        uVar4 = uVar1 / uVar2;
      }
      uVar4 = uVar1 - uVar4 * uVar2;
      uVar5 = uVar4;
      do {
        uVar3 = *(uint *)(*(long *)(lVar10 + 0x38) +
                         (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
        if (uVar3 == uVar1) {
          lVar10 = *(long *)(*(long *)(lVar10 + 0x38) + (long)(int)uVar5 * 0x10 + 8);
          if (lVar10 == 0) {
            return;
          }
          param_1[1] = lVar10;
          return;
        }
        if (uVar3 == 0) {
          return;
        }
        uVar3 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar3 = uVar5 + 1;
        }
        uVar5 = uVar3;
      } while (uVar3 != uVar4);
    }
  }
  return;
}



int FUN_710150c260(long param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  long *plVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  long *plVar9;
  long lVar10;
  long lVar11;
  undefined8 *puVar12;
  
  plVar5 = DAT_7103a5a038;
  if (*(long *)(param_1 + 8) == 0) {
    iVar6 = 0;
  }
  else {
    uVar8 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar8) {
      lVar10 = 0x4b0;
      if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
        lVar10 = 0;
      }
      lVar10 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar10 + 0x20);
      if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
        if (*(uint *)(lVar10 + 0x20) <= uVar8) {
          uVar8 = 0;
        }
        uVar8 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar8 * 0x40 + 0x1c);
        if (uVar8 != 0) {
          puVar12 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
          if (((*DAT_7103a61988 & 1) == 0) &&
             (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar6 != 0)) {
            *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
            thunk_EXT_FUN_02e95df0(DAT_7103a61988);
          }
          lVar10 = (**(code **)*puVar12)(puVar12,DAT_7103a61980);
          uVar1 = *(uint *)(lVar10 + 0x34);
          if (uVar1 != 0) {
            uVar3 = 0;
            if (uVar1 != 0) {
              uVar3 = uVar8 / uVar1;
            }
            uVar3 = uVar8 - uVar3 * uVar1;
            uVar4 = uVar3;
            do {
              uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                               (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
              if (uVar2 == uVar8) {
                plVar9 = *(long **)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                if (((plVar9 != (long *)0x0) &&
                    (*(undefined1 *)((long)(int)plVar9[1] + *plVar9 + -1) = 0,
                    *(char *)*plVar9 != '\0')) &&
                   (uVar8 = *(uint *)((long)plVar9 + 0x5c), -1 < (int)uVar8)) {
                  lVar10 = 0xf0;
                  if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 7) {
                    lVar10 = 0;
                  }
                  lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 + 0x20);
                  lVar10 = *(long *)(lVar11 + 0x28);
                  if (lVar10 != 0) {
                    if (*(uint *)(lVar11 + 0x20) <= uVar8) {
                      uVar8 = 0;
                    }
                    iVar6 = *(int *)(lVar10 + (ulong)uVar8 * 0x10 + 8);
                    goto LAB_710150c3e4;
                  }
                }
                break;
              }
              if (uVar2 == 0) break;
              uVar2 = 0;
              if ((int)(uVar4 + 1) < (int)uVar1) {
                uVar2 = uVar4 + 1;
              }
              uVar4 = uVar2;
            } while (uVar2 != uVar3);
          }
        }
      }
    }
    iVar6 = 0;
LAB_710150c3e4:
    if (*(long *)(param_1 + 8) != 0) {
      uVar8 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
      if (-1 < (int)uVar8) {
        lVar10 = 0x4b0;
        if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
          lVar10 = 0;
        }
        lVar10 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 + 0x20);
        if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
          if (*(uint *)(lVar10 + 0x20) <= uVar8) {
            uVar8 = 0;
          }
          uVar8 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar8 * 0x40 + 0x34);
          if (uVar8 != 0) {
            puVar12 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
            if (((*DAT_7103a61988 & 1) == 0) &&
               (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
              *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
              thunk_EXT_FUN_02e95df0(DAT_7103a61988);
            }
            lVar10 = (**(code **)*puVar12)(puVar12,DAT_7103a61980);
            uVar1 = *(uint *)(lVar10 + 0x34);
            if (uVar1 != 0) {
              uVar3 = 0;
              if (uVar1 != 0) {
                uVar3 = uVar8 / uVar1;
              }
              uVar3 = uVar8 - uVar3 * uVar1;
              uVar4 = uVar3;
              do {
                uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                                 (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4))
                ;
                if (uVar2 == uVar8) {
                  plVar9 = *(long **)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                  if (plVar9 != (long *)0x0) {
                    *(undefined1 *)((long)(int)plVar9[1] + *plVar9 + -1) = 0;
                    if ((*(char *)*plVar9 == '\0') ||
                       (uVar8 = *(uint *)((long)plVar9 + 0x5c), (int)uVar8 < 0)) {
LAB_710150c538:
                      iVar7 = 0;
                    }
                    else {
                      lVar10 = 0xf0;
                      if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 7) {
                        lVar10 = 0;
                      }
                      lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 +
                                        0x20);
                      lVar10 = *(long *)(lVar11 + 0x28);
                      if (lVar10 == 0) goto LAB_710150c538;
                      if (*(uint *)(lVar11 + 0x20) <= uVar8) {
                        uVar8 = 0;
                      }
                      iVar7 = *(int *)(lVar10 + (ulong)uVar8 * 0x10 + 8);
                    }
                    iVar6 = iVar7 + iVar6;
                  }
                  break;
                }
                if (uVar2 == 0) break;
                uVar2 = 0;
                if ((int)(uVar4 + 1) < (int)uVar1) {
                  uVar2 = uVar4 + 1;
                }
                uVar4 = uVar2;
              } while (uVar2 != uVar3);
            }
          }
        }
      }
      if (*(long *)(param_1 + 8) != 0) {
        uVar8 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
        if (-1 < (int)uVar8) {
          lVar10 = 0x4b0;
          if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
            lVar10 = 0;
          }
          lVar10 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 + 0x20);
          if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
            if (*(uint *)(lVar10 + 0x20) <= uVar8) {
              uVar8 = 0;
            }
            uVar8 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar8 * 0x40 + 0x30);
            if (uVar8 != 0) {
              puVar12 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
              if (((*DAT_7103a61988 & 1) == 0) &&
                 (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
                *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
                thunk_EXT_FUN_02e95df0(DAT_7103a61988);
              }
              lVar10 = (**(code **)*puVar12)(puVar12,DAT_7103a61980);
              uVar1 = *(uint *)(lVar10 + 0x34);
              if (uVar1 != 0) {
                uVar3 = 0;
                if (uVar1 != 0) {
                  uVar3 = uVar8 / uVar1;
                }
                uVar3 = uVar8 - uVar3 * uVar1;
                uVar4 = uVar3;
                do {
                  uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                                   (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4
                                   ));
                  if (uVar2 == uVar8) {
                    plVar9 = *(long **)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                    if (plVar9 != (long *)0x0) {
                      *(undefined1 *)((long)(int)plVar9[1] + *plVar9 + -1) = 0;
                      if ((*(char *)*plVar9 == '\0') ||
                         (uVar8 = *(uint *)((long)plVar9 + 0x5c), (int)uVar8 < 0)) {
LAB_710150c698:
                        iVar7 = 0;
                      }
                      else {
                        lVar10 = 0xf0;
                        if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 7) {
                          lVar10 = 0;
                        }
                        lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 +
                                          0x20);
                        lVar10 = *(long *)(lVar11 + 0x28);
                        if (lVar10 == 0) goto LAB_710150c698;
                        if (*(uint *)(lVar11 + 0x20) <= uVar8) {
                          uVar8 = 0;
                        }
                        iVar7 = *(int *)(lVar10 + (ulong)uVar8 * 0x10 + 8);
                      }
                      iVar6 = iVar7 + iVar6;
                    }
                    break;
                  }
                  if (uVar2 == 0) break;
                  uVar2 = 0;
                  if ((int)(uVar4 + 1) < (int)uVar1) {
                    uVar2 = uVar4 + 1;
                  }
                  uVar4 = uVar2;
                } while (uVar2 != uVar3);
              }
            }
          }
        }
        if (*(long *)(param_1 + 8) != 0) {
          uVar8 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
          if (-1 < (int)uVar8) {
            lVar10 = 0x4b0;
            if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
              lVar10 = 0;
            }
            lVar10 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 + 0x20);
            if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
              if (*(uint *)(lVar10 + 0x20) <= uVar8) {
                uVar8 = 0;
              }
              uVar8 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar8 * 0x40 + 0x20);
              if (uVar8 != 0) {
                puVar12 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
                if (((*DAT_7103a61988 & 1) == 0) &&
                   (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
                  *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
                  thunk_EXT_FUN_02e95df0(DAT_7103a61988);
                }
                lVar10 = (**(code **)*puVar12)(puVar12,DAT_7103a61980);
                uVar1 = *(uint *)(lVar10 + 0x34);
                if (uVar1 != 0) {
                  uVar3 = 0;
                  if (uVar1 != 0) {
                    uVar3 = uVar8 / uVar1;
                  }
                  uVar3 = uVar8 - uVar3 * uVar1;
                  uVar4 = uVar3;
                  do {
                    uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                                     (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 |
                                     (ulong)uVar4 << 4));
                    if (uVar2 == uVar8) {
                      plVar9 = *(long **)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                      if (plVar9 != (long *)0x0) {
                        *(undefined1 *)((long)(int)plVar9[1] + *plVar9 + -1) = 0;
                        if ((*(char *)*plVar9 == '\0') ||
                           (uVar8 = *(uint *)((long)plVar9 + 0x5c), (int)uVar8 < 0)) {
LAB_710150c7f4:
                          iVar7 = 0;
                        }
                        else {
                          lVar10 = 0xf0;
                          if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 7) {
                            lVar10 = 0;
                          }
                          lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10
                                            + 0x20);
                          lVar10 = *(long *)(lVar11 + 0x28);
                          if (lVar10 == 0) goto LAB_710150c7f4;
                          if (*(uint *)(lVar11 + 0x20) <= uVar8) {
                            uVar8 = 0;
                          }
                          iVar7 = *(int *)(lVar10 + (ulong)uVar8 * 0x10 + 8);
                        }
                        iVar6 = iVar7 + iVar6;
                      }
                      break;
                    }
                    if (uVar2 == 0) break;
                    uVar2 = 0;
                    if ((int)(uVar4 + 1) < (int)uVar1) {
                      uVar2 = uVar4 + 1;
                    }
                    uVar4 = uVar2;
                  } while (uVar2 != uVar3);
                }
              }
            }
          }
          if (*(long *)(param_1 + 8) != 0) {
            uVar8 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
            if (-1 < (int)uVar8) {
              lVar10 = 0x4b0;
              if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
                lVar10 = 0;
              }
              lVar10 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 + 0x20);
              if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
                if (*(uint *)(lVar10 + 0x20) <= uVar8) {
                  uVar8 = 0;
                }
                uVar8 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar8 * 0x40 + 0x24);
                if (uVar8 != 0) {
                  puVar12 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
                  if (((*DAT_7103a61988 & 1) == 0) &&
                     (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
                    *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
                    thunk_EXT_FUN_02e95df0(DAT_7103a61988);
                  }
                  lVar10 = (**(code **)*puVar12)(puVar12,DAT_7103a61980);
                  uVar1 = *(uint *)(lVar10 + 0x34);
                  if (uVar1 != 0) {
                    uVar3 = 0;
                    if (uVar1 != 0) {
                      uVar3 = uVar8 / uVar1;
                    }
                    uVar3 = uVar8 - uVar3 * uVar1;
                    uVar4 = uVar3;
                    do {
                      uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                                       (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 |
                                       (ulong)uVar4 << 4));
                      if (uVar2 == uVar8) {
                        plVar9 = *(long **)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                        if (plVar9 != (long *)0x0) {
                          *(undefined1 *)((long)(int)plVar9[1] + *plVar9 + -1) = 0;
                          if ((*(char *)*plVar9 == '\0') ||
                             (uVar8 = *(uint *)((long)plVar9 + 0x5c), (int)uVar8 < 0)) {
LAB_710150c950:
                            iVar7 = 0;
                          }
                          else {
                            lVar10 = 0xf0;
                            if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 7) {
                              lVar10 = 0;
                            }
                            lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) +
                                               lVar10 + 0x20);
                            lVar10 = *(long *)(lVar11 + 0x28);
                            if (lVar10 == 0) goto LAB_710150c950;
                            if (*(uint *)(lVar11 + 0x20) <= uVar8) {
                              uVar8 = 0;
                            }
                            iVar7 = *(int *)(lVar10 + (ulong)uVar8 * 0x10 + 8);
                          }
                          iVar6 = iVar7 + iVar6;
                        }
                        break;
                      }
                      if (uVar2 == 0) break;
                      uVar2 = 0;
                      if ((int)(uVar4 + 1) < (int)uVar1) {
                        uVar2 = uVar4 + 1;
                      }
                      uVar4 = uVar2;
                    } while (uVar2 != uVar3);
                  }
                }
              }
            }
            if (*(long *)(param_1 + 8) != 0) {
              uVar8 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
              if (-1 < (int)uVar8) {
                lVar10 = 0x4b0;
                if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
                  lVar10 = 0;
                }
                lVar10 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 + 0x20);
                if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
                  if (*(uint *)(lVar10 + 0x20) <= uVar8) {
                    uVar8 = 0;
                  }
                  uVar8 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar8 * 0x40 + 0x2c);
                  if (uVar8 != 0) {
                    puVar12 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
                    if (((*DAT_7103a61988 & 1) == 0) &&
                       (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
                      *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
                      thunk_EXT_FUN_02e95df0(DAT_7103a61988);
                    }
                    lVar10 = (**(code **)*puVar12)(puVar12,DAT_7103a61980);
                    uVar1 = *(uint *)(lVar10 + 0x34);
                    if (uVar1 != 0) {
                      uVar3 = 0;
                      if (uVar1 != 0) {
                        uVar3 = uVar8 / uVar1;
                      }
                      uVar3 = uVar8 - uVar3 * uVar1;
                      uVar4 = uVar3;
                      do {
                        uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                                         (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 |
                                         (ulong)uVar4 << 4));
                        if (uVar2 == uVar8) {
                          plVar9 = *(long **)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 + 8
                                             );
                          if (plVar9 != (long *)0x0) {
                            *(undefined1 *)((long)(int)plVar9[1] + *plVar9 + -1) = 0;
                            if ((*(char *)*plVar9 == '\0') ||
                               (uVar8 = *(uint *)((long)plVar9 + 0x5c), (int)uVar8 < 0)) {
LAB_710150caac:
                              iVar7 = 0;
                            }
                            else {
                              lVar10 = 0xf0;
                              if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 7) {
                                lVar10 = 0;
                              }
                              lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) +
                                                 lVar10 + 0x20);
                              lVar10 = *(long *)(lVar11 + 0x28);
                              if (lVar10 == 0) goto LAB_710150caac;
                              if (*(uint *)(lVar11 + 0x20) <= uVar8) {
                                uVar8 = 0;
                              }
                              iVar7 = *(int *)(lVar10 + (ulong)uVar8 * 0x10 + 8);
                            }
                            iVar6 = iVar7 + iVar6;
                          }
                          break;
                        }
                        if (uVar2 == 0) break;
                        uVar2 = 0;
                        if ((int)(uVar4 + 1) < (int)uVar1) {
                          uVar2 = uVar4 + 1;
                        }
                        uVar4 = uVar2;
                      } while (uVar2 != uVar3);
                    }
                  }
                }
              }
              if (*(long *)(param_1 + 8) != 0) {
                uVar8 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
                if (-1 < (int)uVar8) {
                  lVar10 = 0x4b0;
                  if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
                    lVar10 = 0;
                  }
                  lVar10 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 + 0x20);
                  if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
                    if (*(uint *)(lVar10 + 0x20) <= uVar8) {
                      uVar8 = 0;
                    }
                    uVar8 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar8 * 0x40 + 0x18);
                    if (uVar8 != 0) {
                      puVar12 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
                      if (((*DAT_7103a61988 & 1) == 0) &&
                         (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
                        *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
                        thunk_EXT_FUN_02e95df0(DAT_7103a61988);
                      }
                      lVar10 = (**(code **)*puVar12)(puVar12,DAT_7103a61980);
                      uVar1 = *(uint *)(lVar10 + 0x34);
                      if (uVar1 != 0) {
                        uVar3 = 0;
                        if (uVar1 != 0) {
                          uVar3 = uVar8 / uVar1;
                        }
                        uVar3 = uVar8 - uVar3 * uVar1;
                        uVar4 = uVar3;
                        do {
                          uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                                           (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 |
                                           (ulong)uVar4 << 4));
                          if (uVar2 == uVar8) {
                            plVar9 = *(long **)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 +
                                               8);
                            if (plVar9 != (long *)0x0) {
                              *(undefined1 *)((long)(int)plVar9[1] + *plVar9 + -1) = 0;
                              if ((*(char *)*plVar9 == '\0') ||
                                 (uVar8 = *(uint *)((long)plVar9 + 0x5c), (int)uVar8 < 0)) {
LAB_710150cc08:
                                iVar7 = 0;
                              }
                              else {
                                lVar10 = 0xf0;
                                if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 7) {
                                  lVar10 = 0;
                                }
                                lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) +
                                                   lVar10 + 0x20);
                                lVar10 = *(long *)(lVar11 + 0x28);
                                if (lVar10 == 0) goto LAB_710150cc08;
                                if (*(uint *)(lVar11 + 0x20) <= uVar8) {
                                  uVar8 = 0;
                                }
                                iVar7 = *(int *)(lVar10 + (ulong)uVar8 * 0x10 + 8);
                              }
                              iVar6 = iVar7 + iVar6;
                            }
                            break;
                          }
                          if (uVar2 == 0) break;
                          uVar2 = 0;
                          if ((int)(uVar4 + 1) < (int)uVar1) {
                            uVar2 = uVar4 + 1;
                          }
                          uVar4 = uVar2;
                        } while (uVar2 != uVar3);
                      }
                    }
                  }
                }
                if ((*(long *)(param_1 + 8) != 0) &&
                   (uVar8 = *(uint *)(*(long *)(param_1 + 8) + 0x1c), -1 < (int)uVar8)) {
                  lVar10 = 0x4b0;
                  if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
                    lVar10 = 0;
                  }
                  lVar10 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar10 + 0x20);
                  if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
                    if (*(uint *)(lVar10 + 0x20) <= uVar8) {
                      uVar8 = 0;
                    }
                    uVar8 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar8 * 0x40 + 0x28);
                    if (uVar8 != 0) {
                      puVar12 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
                      if (((*DAT_7103a61988 & 1) == 0) &&
                         (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
                        *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
                        thunk_EXT_FUN_02e95df0(DAT_7103a61988);
                      }
                      lVar10 = (**(code **)*puVar12)(puVar12,DAT_7103a61980);
                      uVar1 = *(uint *)(lVar10 + 0x34);
                      if (uVar1 != 0) {
                        uVar3 = 0;
                        if (uVar1 != 0) {
                          uVar3 = uVar8 / uVar1;
                        }
                        uVar3 = uVar8 - uVar3 * uVar1;
                        uVar4 = uVar3;
                        do {
                          uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                                           (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 |
                                           (ulong)uVar4 << 4));
                          if (uVar2 == uVar8) {
                            plVar9 = *(long **)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 +
                                               8);
                            if (plVar9 == (long *)0x0) {
                              return iVar6;
                            }
                            *(undefined1 *)((long)(int)plVar9[1] + *plVar9 + -1) = 0;
                            if ((*(char *)*plVar9 != '\0') &&
                               (uVar8 = *(uint *)((long)plVar9 + 0x5c), -1 < (int)uVar8)) {
                              lVar10 = 0xf0;
                              if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 7) {
                                lVar10 = 0;
                              }
                              lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) +
                                                 lVar10 + 0x20);
                              lVar10 = *(long *)(lVar11 + 0x28);
                              if (lVar10 != 0) {
                                if (*(uint *)(lVar11 + 0x20) <= uVar8) {
                                  uVar8 = 0;
                                }
                                iVar7 = *(int *)(lVar10 + (ulong)uVar8 * 0x10 + 8);
                                goto LAB_710150cd6c;
                              }
                            }
                            iVar7 = 0;
LAB_710150cd6c:
                            return iVar7 + iVar6;
                          }
                          if (uVar2 == 0) {
                            return iVar6;
                          }
                          uVar2 = 0;
                          if ((int)(uVar4 + 1) < (int)uVar1) {
                            uVar2 = uVar4 + 1;
                          }
                          uVar4 = uVar2;
                        } while (uVar2 != uVar3);
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
  return iVar6;
}



undefined8 FUN_710150d040(long param_1,ulong param_2,long param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined8 uVar7;
  undefined8 *puVar8;
  ulong uVar9;
  long lVar10;
  
  uVar9 = param_2 & 0xffffffff;
  if (*(long *)(param_1 + 8) == 0 || uVar9 == 0xffffffff) {
    return 0;
  }
  uVar5 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
  if (-1 < (int)uVar5) {
    lVar10 = 0x4b0;
    if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
      lVar10 = 0;
    }
    lVar10 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar10 + 0x20);
    if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
      if (*(uint *)(lVar10 + 0x20) <= uVar5) {
        uVar5 = 0;
      }
      uVar7 = (**(code **)(&DAT_7103959d70 + (-(uVar9 >> 0x1f) & 0xfffffff000000000 | uVar9 << 4)))
                        (*(long *)(lVar10 + 0x28) + (ulong)uVar5 * 0x40);
      uVar5 = (uint)uVar7;
      if (uVar5 == 0) {
        return uVar7;
      }
      puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
      if (((*DAT_7103a61988 & 1) == 0) &&
         (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar6 != 0)) {
        *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a61988);
      }
      lVar10 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
      uVar1 = *(uint *)(lVar10 + 0x34);
      if (uVar1 != 0) {
        uVar3 = 0;
        if (uVar1 != 0) {
          uVar3 = uVar5 / uVar1;
        }
        uVar3 = uVar5 - uVar3 * uVar1;
        uVar4 = uVar3;
        while( true ) {
          uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                           (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
          if (uVar2 == uVar5) break;
          if (uVar2 == 0) {
            return 0;
          }
          uVar2 = 0;
          if ((int)(uVar4 + 1) < (int)uVar1) {
            uVar2 = uVar4 + 1;
          }
          uVar4 = uVar2;
          if (uVar2 == uVar3) {
            return 0;
          }
        }
        lVar10 = *(long *)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
        if (lVar10 != 0) {
          *(long *)(param_3 + 8) = lVar10;
          return 1;
        }
      }
    }
  }
  return 0;
}



ulong FUN_710150d230(long param_1,ulong param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined8 *puVar7;
  ulong uVar8;
  long lVar9;
  
  uVar8 = param_2 & 0xffffffff;
  if (*(long *)(param_1 + 8) == 0 || uVar8 == 0xffffffff) {
    return 0;
  }
  uVar5 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
  if (-1 < (int)uVar5) {
    lVar9 = 0x4b0;
    if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
      lVar9 = 0;
    }
    lVar9 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar9 + 0x20);
    if ((lVar9 != 0) && (*(long *)(lVar9 + 0x28) != 0)) {
      if (*(uint *)(lVar9 + 0x20) <= uVar5) {
        uVar5 = 0;
      }
      uVar8 = (**(code **)(&DAT_7103959d70 + (-(uVar8 >> 0x1f) & 0xfffffff000000000 | uVar8 << 4)))
                        (*(long *)(lVar9 + 0x28) + (ulong)uVar5 * 0x40);
      uVar5 = (uint)uVar8;
      if (uVar5 == 0) {
        return uVar8;
      }
      puVar7 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
      if (((*DAT_7103a61988 & 1) == 0) &&
         (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar6 != 0)) {
        *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a61988);
      }
      lVar9 = (**(code **)*puVar7)(puVar7,DAT_7103a61980);
      uVar1 = *(uint *)(lVar9 + 0x34);
      if (uVar1 != 0) {
        uVar3 = 0;
        if (uVar1 != 0) {
          uVar3 = uVar5 / uVar1;
        }
        uVar3 = uVar5 - uVar3 * uVar1;
        uVar4 = uVar3;
        while( true ) {
          uVar2 = *(uint *)(*(long *)(lVar9 + 0x28) +
                           (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
          if (uVar2 == uVar5) {
            return (ulong)(*(long *)(*(long *)(lVar9 + 0x28) + (long)(int)uVar4 * 0x10 + 8) != 0);
          }
          if (uVar2 == 0) break;
          uVar2 = 0;
          if ((int)(uVar4 + 1) < (int)uVar1) {
            uVar2 = uVar4 + 1;
          }
          uVar4 = uVar2;
          if (uVar2 == uVar3) {
            return 0;
          }
        }
        return 0;
      }
    }
  }
  return 0;
}



ulong FUN_710150d3d0(long param_1,uint *param_2)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  ulong uVar8;
  undefined8 *puVar9;
  long lVar10;
  undefined8 uStack_30;
  long local_28;
  
  FUN_71015081f0(&uStack_30,param_2);
  if (local_28 != 0) {
    if (*(long *)(param_1 + 8) == 0) {
      return 0;
    }
    if (*(int *)(local_28 + 0x54) == -1) {
      return 0;
    }
    uVar6 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar6) {
      lVar10 = 0x4b0;
      if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
        lVar10 = 0;
      }
      lVar10 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar10 + 0x20);
      if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
        if (*(uint *)(lVar10 + 0x20) <= uVar6) {
          uVar6 = 0;
        }
        uVar8 = (**(code **)(&DAT_7103959d70 + (long)*(int *)(local_28 + 0x54) * 0x10))
                          (*(long *)(lVar10 + 0x28) + (ulong)uVar6 * 0x40);
        uVar6 = (uint)uVar8;
        if (uVar6 == 0) {
          return uVar8;
        }
        puVar9 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
        if (((*DAT_7103a61988 & 1) == 0) &&
           (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
          *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
          thunk_EXT_FUN_02e95df0(DAT_7103a61988);
        }
        lVar10 = (**(code **)*puVar9)(puVar9,DAT_7103a61980);
        uVar2 = *(uint *)(lVar10 + 0x34);
        if (uVar2 != 0) {
          uVar4 = 0;
          if (uVar2 != 0) {
            uVar4 = uVar6 / uVar2;
          }
          uVar4 = uVar6 - uVar4 * uVar2;
          uVar5 = uVar4;
          while( true ) {
            uVar3 = *(uint *)(*(long *)(lVar10 + 0x28) +
                             (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
            if (uVar3 == uVar6) break;
            if (uVar3 == 0) {
              return 0;
            }
            uVar3 = 0;
            if ((int)(uVar5 + 1) < (int)uVar2) {
              uVar3 = uVar5 + 1;
            }
            uVar5 = uVar3;
            if (uVar3 == uVar4) {
              return 0;
            }
          }
          lVar10 = *(long *)(*(long *)(lVar10 + 0x28) + (long)(int)uVar5 * 0x10 + 8);
          if (lVar10 != 0) {
            piVar1 = DAT_7103a5d098;
            if (local_28 != 0) {
              piVar1 = (int *)(local_28 + 0x50);
            }
            return (ulong)(*piVar1 == *(int *)(lVar10 + 0x50));
          }
        }
      }
    }
  }
  return 0;
}



undefined8 FUN_710150d5b0(long param_1,uint *param_2,uint param_3)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  uint uVar5;
  int iVar6;
  undefined8 uVar7;
  undefined8 *puVar8;
  uint uVar9;
  long lVar10;
  uint uVar11;
  undefined8 uStack_50;
  long local_48;
  
  FUN_71015081f0(&uStack_50,param_2);
  if (local_48 != 0) {
    if (*(long *)(param_1 + 8) == 0) {
      return 0;
    }
    if (*(int *)(local_48 + 0x54) == -1) {
      return 0;
    }
    uVar5 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar5) {
      lVar10 = 0x4b0;
      if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
        lVar10 = 0;
      }
      lVar10 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar10 + 0x20);
      if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
        if (*(uint *)(lVar10 + 0x20) <= uVar5) {
          uVar5 = 0;
        }
        uVar7 = (**(code **)(&DAT_7103959d70 + (long)*(int *)(local_48 + 0x54) * 0x10))
                          (*(long *)(lVar10 + 0x28) + (ulong)uVar5 * 0x40);
        uVar5 = (uint)uVar7;
        if (uVar5 == 0) {
          return uVar7;
        }
        puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
        if (((*DAT_7103a61988 & 1) == 0) &&
           (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar6 != 0)) {
          *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
          thunk_EXT_FUN_02e95df0(DAT_7103a61988);
        }
        lVar10 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
        uVar11 = *(uint *)(lVar10 + 0x34);
        if (uVar11 != 0) {
          uVar9 = 0;
          if (uVar11 != 0) {
            uVar9 = uVar5 / uVar11;
          }
          uVar9 = uVar5 - uVar9 * uVar11;
          uVar3 = uVar9;
          while( true ) {
            uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                             (-(ulong)(uVar3 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar3 << 4));
            if (uVar2 == uVar5) break;
            if (uVar2 == 0) {
              return 0;
            }
            uVar2 = 0;
            if ((int)(uVar3 + 1) < (int)uVar11) {
              uVar2 = uVar3 + 1;
            }
            uVar3 = uVar2;
            if (uVar2 == uVar9) {
              return 0;
            }
          }
          lVar10 = *(long *)(*(long *)(lVar10 + 0x28) + (long)(int)uVar3 * 0x10 + 8);
          if (lVar10 != 0) {
            piVar1 = DAT_7103a5d098;
            if (local_48 != 0) {
              piVar1 = (int *)(local_48 + 0x50);
            }
            if (*piVar1 == *(int *)(lVar10 + 0x50)) {
              if ((*(long *)(param_1 + 8) == 0) ||
                 (lVar10 = FUN_710150f7dc(*(long *)(param_1 + 8)), lVar10 == 0)) {
                uVar5 = 1;
              }
              else {
                uVar5 = FUN_7102813278((undefined8 *)(lVar10 + 8));
                if ((int)uVar5 < 1) {
                  return 0;
                }
              }
              uVar11 = 0;
              while( true ) {
                if (local_48 == 0) {
                  uVar9 = 0xffffffff;
                }
                else {
                  uVar9 = *(uint *)(local_48 + 0x54);
                }
                uVar7 = FUN_710150d8d4(param_1,uVar9,uVar11);
                if ((param_3 & ((int)param_3 >> 0x1f ^ 0xffffffffU)) == (uint)uVar7) break;
                bVar4 = uVar5 - 1 == uVar11;
                uVar11 = uVar11 + 1;
                if (bVar4) {
                  return 0;
                }
              }
              return 1;
            }
          }
        }
      }
    }
  }
  return 0;
}



uint FUN_710150d804(long param_1)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  long lVar4;
  
  if ((*(long *)(param_1 + 8) != 0) &&
     (uVar1 = *(uint *)(*(long *)(param_1 + 8) + 0x1c), -1 < (int)uVar1)) {
    lVar4 = 0x4b0;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1f) {
      lVar4 = 0;
    }
    lVar4 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar4 + 0x20);
    if ((lVar4 != 0) && (*(long *)(lVar4 + 0x28) != 0)) {
      if (*(uint *)(lVar4 + 0x20) <= uVar1) {
        uVar1 = 0;
      }
      lVar4 = *(long *)(lVar4 + 0x28) + (ulong)uVar1 * 0x40;
      bVar2 = *(byte *)(lVar4 + 0x14);
      if (((((bVar2 & 0xf7) != 0xc0) && (bVar2 != 0xc1)) && (bVar2 != 0xc4)) &&
         ((bVar2 & 0xe0) != 0x20)) {
        return 0;
      }
      uVar1 = *(uint *)((long)*(short **)(lVar4 + 8) + (ulong)*(uint *)(lVar4 + 0x10));
      uVar3 = uVar1 >> 8;
      if (**(short **)(lVar4 + 8) != 0x5942) {
        return uVar3;
      }
      return uVar3 & 0xff00 | uVar1 >> 0x18 | (uVar3 & 0xff) << 0x10;
    }
  }
  return 1;
}



undefined8 FUN_710150d8d4(long param_1,uint param_2,uint param_3)

{
  uint uVar1;
  byte bVar2;
  undefined1 *puVar3;
  uint uVar4;
  short *psVar5;
  long lVar6;
  undefined1 auVar7 [16];
  long local_30;
  undefined4 local_28;
  undefined1 local_24;
  
  if ((*(long *)(param_1 + 8) != 0 && param_2 != 0xffffffff) &&
     (uVar4 = *(uint *)(*(long *)(param_1 + 8) + 0x1c), -1 < (int)uVar4)) {
    lVar6 = 0x4b0;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1f) {
      lVar6 = 0;
    }
    lVar6 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar6 + 0x20);
    if ((lVar6 != 0) && (*(long *)(lVar6 + 0x28) != 0)) {
      if (*(uint *)(lVar6 + 0x20) <= uVar4) {
        uVar4 = 0;
      }
      lVar6 = *(long *)(lVar6 + 0x28) + (ulong)uVar4 * 0x40;
      bVar2 = *(byte *)(lVar6 + 0x14);
      if (((((bVar2 & 0xf7) == 0xc0) || (bVar2 == 0xc1)) || (bVar2 == 0xc4)) ||
         ((bVar2 & 0xe0) == 0x20)) {
        psVar5 = *(short **)(lVar6 + 8);
        uVar1 = *(uint *)((long)psVar5 + (ulong)*(uint *)(lVar6 + 0x10));
        uVar4 = uVar1 >> 8;
        if (*psVar5 == 0x5942) {
          uVar4 = uVar4 & 0xff00 | uVar1 >> 0x18 | (uVar4 & 0xff) << 0x10;
        }
        if (uVar4 != 0) {
          auVar7 = FUN_71028132dc((undefined8 *)(lVar6 + 8),
                                  param_3 & ((int)param_3 >> 0x1f ^ 0xffffffffU));
          local_30 = auVar7._0_8_;
          local_28 = auVar7._8_4_;
          local_24 = auVar7[0xc];
          if (local_30 != 0) {
            if (param_2 < 8) {
              puVar3 = *(undefined1 **)(DAT_7103a61258 + (ulong)(param_2 + 1) * 8 + 0x50);
            }
            else {
              puVar3 = &DAT_71030e70e0;
            }
            auVar7 = FUN_7102813520(&local_30,puVar3);
            uVar4 = auVar7._12_4_ & 0xff;
            if (uVar4 == 0xd3) {
              return auVar7._8_8_;
            }
            if ((uVar4 == 0xd1) && (-1 < auVar7._8_4_)) {
              return auVar7._8_8_;
            }
          }
        }
      }
    }
  }
  return 0;
}



uint FUN_710150da40(long param_1,ulong param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined8 *puVar7;
  ulong uVar8;
  long lVar9;
  
  uVar8 = param_2 & 0xffffffff;
  if ((*(long *)(param_1 + 8) != 0 && uVar8 != 0xffffffff) &&
     (uVar5 = *(uint *)(*(long *)(param_1 + 8) + 0x1c), -1 < (int)uVar5)) {
    lVar9 = 0x4b0;
    if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
      lVar9 = 0;
    }
    lVar9 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar9 + 0x20);
    if ((lVar9 != 0) && (*(long *)(lVar9 + 0x28) != 0)) {
      if (*(uint *)(lVar9 + 0x20) <= uVar5) {
        uVar5 = 0;
      }
      uVar5 = (**(code **)(&DAT_7103959d70 + (-(uVar8 >> 0x1f) & 0xfffffff000000000 | uVar8 << 4)))
                        (*(long *)(lVar9 + 0x28) + (ulong)uVar5 * 0x40);
      if (uVar5 != 0) {
        puVar7 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
        if (((*DAT_7103a61988 & 1) == 0) &&
           (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar6 != 0)) {
          *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
          thunk_EXT_FUN_02e95df0(DAT_7103a61988);
        }
        lVar9 = (**(code **)*puVar7)(puVar7,DAT_7103a61980);
        uVar1 = *(uint *)(lVar9 + 0x34);
        if (uVar1 != 0) {
          uVar3 = 0;
          if (uVar1 != 0) {
            uVar3 = uVar5 / uVar1;
          }
          uVar3 = uVar5 - uVar3 * uVar1;
          uVar4 = uVar3;
          do {
            uVar2 = *(uint *)(*(long *)(lVar9 + 0x28) +
                             (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
            if (uVar2 == uVar5) {
              if (*(long *)(*(long *)(lVar9 + 0x28) + (long)(int)uVar4 * 0x10 + 8) == 0) {
                return 0;
              }
              return uVar5;
            }
            if (uVar2 == 0) {
              return 0;
            }
            uVar2 = 0;
            if ((int)(uVar4 + 1) < (int)uVar1) {
              uVar2 = uVar4 + 1;
            }
            uVar4 = uVar2;
          } while (uVar2 != uVar3);
        }
      }
    }
  }
  return 0;
}



undefined4 FUN_710150dbd0(long param_1,uint param_2,ulong param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined8 *puVar8;
  undefined8 uVar9;
  long lVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  
  if ((*(long *)(param_1 + 8) != 0) &&
     (uVar6 = *(uint *)(*(long *)(param_1 + 8) + 0x1c), -1 < (int)uVar6)) {
    lVar10 = 0x4b0;
    if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
      lVar10 = 0;
    }
    lVar10 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar10 + 0x20);
    if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
      if (*(uint *)(lVar10 + 0x20) <= uVar6) {
        uVar6 = 0;
      }
      uVar6 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar6 * 0x40 + 0x38);
      if ((uVar6 != 0xffffffff) &&
         (uVar5 = (**(code **)(&DAT_7103959d70 + (long)(int)uVar6 * 0x10))(), uVar5 != 0)) {
        puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
        if (((*DAT_7103a61988 & 1) == 0) &&
           (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
          *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
          thunk_EXT_FUN_02e95df0(DAT_7103a61988);
        }
        lVar10 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
        uVar1 = *(uint *)(lVar10 + 0x34);
        if (uVar1 != 0) {
          uVar3 = 0;
          if (uVar1 != 0) {
            uVar3 = uVar5 / uVar1;
          }
          uVar3 = uVar5 - uVar3 * uVar1;
          uVar4 = uVar3;
          do {
            uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                             (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
            if (uVar2 == uVar5) {
              lVar10 = *(long *)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
              if (lVar10 == 0) {
                return 0;
              }
              uVar9 = FUN_710150d8d4(param_1,uVar6,param_2);
              uVar6 = FUN_710150b8c0(lVar10,(uint)uVar9);
              lVar10 = (long)(int)uVar6 * 0x10;
              uVar12 = *(undefined4 *)(&DAT_71032af324 + lVar10);
              uVar13 = *(undefined4 *)(&DAT_71032af328 + lVar10);
              if ((param_3 & 1) == 0) {
                return *(undefined4 *)(&DAT_71032af320 + lVar10);
              }
              uVar11 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(&DAT_71032af320 + lVar10),0x400ccccd);
              thunk_EXT_FUN_02e95df0(uVar12,0x400ccccd);
              thunk_EXT_FUN_02e95df0(uVar13,0x400ccccd);
              return uVar11;
            }
            if (uVar2 == 0) {
              return 0;
            }
            uVar2 = 0;
            if ((int)(uVar4 + 1) < (int)uVar1) {
              uVar2 = uVar4 + 1;
            }
            uVar4 = uVar2;
          } while (uVar2 != uVar3);
        }
      }
    }
  }
  return 0;
}



uint FUN_710150de10(long param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined8 *puVar8;
  undefined8 uVar9;
  long lVar10;
  
  if ((*(long *)(param_1 + 8) != 0) &&
     (uVar6 = *(uint *)(*(long *)(param_1 + 8) + 0x1c), -1 < (int)uVar6)) {
    lVar10 = 0x4b0;
    if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
      lVar10 = 0;
    }
    lVar10 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar10 + 0x20);
    if ((lVar10 != 0) && (*(long *)(lVar10 + 0x28) != 0)) {
      if (*(uint *)(lVar10 + 0x20) <= uVar6) {
        uVar6 = 0;
      }
      uVar6 = *(uint *)(*(long *)(lVar10 + 0x28) + (ulong)uVar6 * 0x40 + 0x38);
      if ((uVar6 != 0xffffffff) &&
         (uVar5 = (**(code **)(&DAT_7103959d70 + (long)(int)uVar6 * 0x10))(), uVar5 != 0)) {
        puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
        if (((*DAT_7103a61988 & 1) == 0) &&
           (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
          *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
          thunk_EXT_FUN_02e95df0(DAT_7103a61988);
        }
        lVar10 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
        uVar1 = *(uint *)(lVar10 + 0x34);
        if (uVar1 != 0) {
          uVar3 = 0;
          if (uVar1 != 0) {
            uVar3 = uVar5 / uVar1;
          }
          uVar3 = uVar5 - uVar3 * uVar1;
          uVar4 = uVar3;
          do {
            uVar2 = *(uint *)(*(long *)(lVar10 + 0x28) +
                             (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
            if (uVar2 == uVar5) {
              lVar10 = *(long *)(*(long *)(lVar10 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
              if (lVar10 == 0) {
                return 0;
              }
              uVar9 = FUN_710150d8d4(param_1,uVar6,param_2);
              uVar6 = FUN_710150b8c0(lVar10,(uint)uVar9);
              return uVar6;
            }
            if (uVar2 == 0) {
              return 0;
            }
            uVar2 = 0;
            if ((int)(uVar4 + 1) < (int)uVar1) {
              uVar2 = uVar4 + 1;
            }
            uVar4 = uVar2;
          } while (uVar2 != uVar3);
        }
      }
    }
  }
  return 0;
}



undefined8 FUN_710150dfd0(long param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  long *plVar5;
  bool bVar6;
  int iVar7;
  undefined8 *puVar8;
  ulong uVar9;
  uint uVar10;
  long lVar11;
  long local_40;
  long local_38;
  
  plVar5 = DAT_7103a5a038;
  local_40 = DAT_7103a61968 + 0x10;
  local_38 = 0;
  if (*(long *)(param_1 + 8) != 0) {
    uVar10 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar10) {
      lVar11 = 0x4b0;
      if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
        lVar11 = 0;
      }
      lVar11 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar11 + 0x20);
      if ((lVar11 != 0) && (*(long *)(lVar11 + 0x28) != 0)) {
        if (*(uint *)(lVar11 + 0x20) <= uVar10) {
          uVar10 = 0;
        }
        uVar10 = *(uint *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x40 + 0x1c);
        if (uVar10 != 0) {
          puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
          if (((*DAT_7103a61988 & 1) == 0) &&
             (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
            *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
            thunk_EXT_FUN_02e95df0(DAT_7103a61988);
          }
          lVar11 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
          uVar1 = *(uint *)(lVar11 + 0x34);
          if (uVar1 != 0) {
            uVar3 = 0;
            if (uVar1 != 0) {
              uVar3 = uVar10 / uVar1;
            }
            uVar3 = uVar10 - uVar3 * uVar1;
            uVar4 = uVar3;
            do {
              uVar2 = *(uint *)(*(long *)(lVar11 + 0x28) +
                               (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
              if (uVar2 == uVar10) {
                lVar11 = *(long *)(*(long *)(lVar11 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                if ((lVar11 != 0) &&
                   (uVar10 = *(uint *)(lVar11 + 100), local_38 = lVar11, -1 < (int)uVar10)) {
                  lVar11 = 0x460;
                  if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1d) {
                    lVar11 = 0;
                  }
                  lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
                  if (*(uint *)(lVar11 + 0x20) <= uVar10) {
                    uVar10 = 0;
                  }
                  if (*(char *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x48 + 0x42) != '\0') {
                    return 1;
                  }
                }
                break;
              }
              if (uVar2 == 0) break;
              uVar2 = 0;
              if ((int)(uVar4 + 1) < (int)uVar1) {
                uVar2 = uVar4 + 1;
              }
              uVar4 = uVar2;
            } while (uVar2 != uVar3);
          }
        }
      }
    }
    if (*(long *)(param_1 + 8) == 0) {
      return 0;
    }
    uVar10 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar10) {
      lVar11 = 0x4b0;
      if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
        lVar11 = 0;
      }
      lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
      if ((lVar11 != 0) && (*(long *)(lVar11 + 0x28) != 0)) {
        if (*(uint *)(lVar11 + 0x20) <= uVar10) {
          uVar10 = 0;
        }
        uVar10 = *(uint *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x40 + 0x34);
        if (uVar10 != 0) {
          puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
          if (((*DAT_7103a61988 & 1) == 0) &&
             (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
            *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
            thunk_EXT_FUN_02e95df0(DAT_7103a61988);
          }
          lVar11 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
          uVar1 = *(uint *)(lVar11 + 0x34);
          if (uVar1 != 0) {
            uVar3 = 0;
            if (uVar1 != 0) {
              uVar3 = uVar10 / uVar1;
            }
            uVar3 = uVar10 - uVar3 * uVar1;
            uVar4 = uVar3;
            do {
              uVar2 = *(uint *)(*(long *)(lVar11 + 0x28) +
                               (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
              if (uVar2 == uVar10) {
                lVar11 = *(long *)(*(long *)(lVar11 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                if ((lVar11 != 0) &&
                   (uVar10 = *(uint *)(lVar11 + 100), local_38 = lVar11, -1 < (int)uVar10)) {
                  lVar11 = 0x460;
                  if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1d) {
                    lVar11 = 0;
                  }
                  lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
                  if (*(uint *)(lVar11 + 0x20) <= uVar10) {
                    uVar10 = 0;
                  }
                  if (*(char *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x48 + 0x42) != '\0') {
                    return 1;
                  }
                }
                break;
              }
              if (uVar2 == 0) break;
              uVar2 = 0;
              if ((int)(uVar4 + 1) < (int)uVar1) {
                uVar2 = uVar4 + 1;
              }
              uVar4 = uVar2;
            } while (uVar2 != uVar3);
          }
        }
      }
    }
    if (*(long *)(param_1 + 8) == 0) {
      return 0;
    }
    uVar10 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar10) {
      lVar11 = 0x4b0;
      if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
        lVar11 = 0;
      }
      lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
      if ((lVar11 != 0) && (*(long *)(lVar11 + 0x28) != 0)) {
        if (*(uint *)(lVar11 + 0x20) <= uVar10) {
          uVar10 = 0;
        }
        uVar10 = *(uint *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x40 + 0x30);
        if (uVar10 != 0) {
          puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
          if (((*DAT_7103a61988 & 1) == 0) &&
             (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
            *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
            thunk_EXT_FUN_02e95df0(DAT_7103a61988);
          }
          lVar11 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
          uVar1 = *(uint *)(lVar11 + 0x34);
          if (uVar1 != 0) {
            uVar3 = 0;
            if (uVar1 != 0) {
              uVar3 = uVar10 / uVar1;
            }
            uVar3 = uVar10 - uVar3 * uVar1;
            uVar4 = uVar3;
            do {
              uVar2 = *(uint *)(*(long *)(lVar11 + 0x28) +
                               (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
              if (uVar2 == uVar10) {
                lVar11 = *(long *)(*(long *)(lVar11 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                if ((lVar11 != 0) &&
                   (uVar10 = *(uint *)(lVar11 + 100), local_38 = lVar11, -1 < (int)uVar10)) {
                  lVar11 = 0x460;
                  if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1d) {
                    lVar11 = 0;
                  }
                  lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
                  if (*(uint *)(lVar11 + 0x20) <= uVar10) {
                    uVar10 = 0;
                  }
                  if (*(char *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x48 + 0x42) != '\0') {
                    return 1;
                  }
                }
                break;
              }
              if (uVar2 == 0) break;
              uVar2 = 0;
              if ((int)(uVar4 + 1) < (int)uVar1) {
                uVar2 = uVar4 + 1;
              }
              uVar4 = uVar2;
            } while (uVar2 != uVar3);
          }
        }
      }
    }
    if (*(long *)(param_1 + 8) == 0) {
      return 0;
    }
    uVar10 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar10) {
      lVar11 = 0x4b0;
      if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
        lVar11 = 0;
      }
      lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
      if ((lVar11 != 0) && (*(long *)(lVar11 + 0x28) != 0)) {
        if (*(uint *)(lVar11 + 0x20) <= uVar10) {
          uVar10 = 0;
        }
        uVar10 = *(uint *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x40 + 0x20);
        if (uVar10 != 0) {
          puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
          if (((*DAT_7103a61988 & 1) == 0) &&
             (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
            *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
            thunk_EXT_FUN_02e95df0(DAT_7103a61988);
          }
          lVar11 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
          uVar1 = *(uint *)(lVar11 + 0x34);
          if (uVar1 != 0) {
            uVar3 = 0;
            if (uVar1 != 0) {
              uVar3 = uVar10 / uVar1;
            }
            uVar3 = uVar10 - uVar3 * uVar1;
            uVar4 = uVar3;
            do {
              uVar2 = *(uint *)(*(long *)(lVar11 + 0x28) +
                               (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
              if (uVar2 == uVar10) {
                lVar11 = *(long *)(*(long *)(lVar11 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                if ((lVar11 != 0) &&
                   (uVar10 = *(uint *)(lVar11 + 100), local_38 = lVar11, -1 < (int)uVar10)) {
                  lVar11 = 0x460;
                  if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1d) {
                    lVar11 = 0;
                  }
                  lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
                  if (*(uint *)(lVar11 + 0x20) <= uVar10) {
                    uVar10 = 0;
                  }
                  if (*(char *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x48 + 0x42) != '\0') {
                    return 1;
                  }
                }
                break;
              }
              if (uVar2 == 0) break;
              uVar2 = 0;
              if ((int)(uVar4 + 1) < (int)uVar1) {
                uVar2 = uVar4 + 1;
              }
              uVar4 = uVar2;
            } while (uVar2 != uVar3);
          }
        }
      }
    }
    if (*(long *)(param_1 + 8) == 0) {
      return 0;
    }
    uVar10 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar10) {
      lVar11 = 0x4b0;
      if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
        lVar11 = 0;
      }
      lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
      if ((lVar11 != 0) && (*(long *)(lVar11 + 0x28) != 0)) {
        if (*(uint *)(lVar11 + 0x20) <= uVar10) {
          uVar10 = 0;
        }
        uVar10 = *(uint *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x40 + 0x24);
        if (uVar10 != 0) {
          puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
          if (((*DAT_7103a61988 & 1) == 0) &&
             (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar7 != 0)) {
            *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
            thunk_EXT_FUN_02e95df0(DAT_7103a61988);
          }
          lVar11 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
          uVar1 = *(uint *)(lVar11 + 0x34);
          if (uVar1 != 0) {
            uVar3 = 0;
            if (uVar1 != 0) {
              uVar3 = uVar10 / uVar1;
            }
            uVar3 = uVar10 - uVar3 * uVar1;
            uVar4 = uVar3;
            do {
              uVar2 = *(uint *)(*(long *)(lVar11 + 0x28) +
                               (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
              if (uVar2 == uVar10) {
                lVar11 = *(long *)(*(long *)(lVar11 + 0x28) + (long)(int)uVar4 * 0x10 + 8);
                if ((lVar11 != 0) &&
                   (local_38 = lVar11, bVar6 = FUN_7101508674((long)&local_40), bVar6)) {
                  return 1;
                }
                break;
              }
              if (uVar2 == 0) break;
              uVar2 = 0;
              if ((int)(uVar4 + 1) < (int)uVar1) {
                uVar2 = uVar4 + 1;
              }
              uVar4 = uVar2;
            } while (uVar2 != uVar3);
          }
        }
      }
    }
    if (*(long *)(param_1 + 8) == 0) {
      return 0;
    }
    uVar10 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar10) {
      lVar11 = 0x4b0;
      if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
        lVar11 = 0;
      }
      lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
      if ((lVar11 != 0) && (*(long *)(lVar11 + 0x28) != 0)) {
        if (*(uint *)(lVar11 + 0x20) <= uVar10) {
          uVar10 = 0;
        }
        uVar10 = *(uint *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x40 + 0x2c);
        if (uVar10 != 0) {
          lVar11 = FUN_7101512540(*DAT_7103a59ec8);
          uVar9 = FUN_710150aeb0(lVar11,(long)&local_40,uVar10);
          if (((uVar9 & 1) != 0) && (bVar6 = FUN_7101508674((long)&local_40), bVar6)) {
            return 1;
          }
        }
      }
    }
    if (*(long *)(param_1 + 8) == 0) {
      return 0;
    }
    uVar10 = *(uint *)(*(long *)(param_1 + 8) + 0x1c);
    if (-1 < (int)uVar10) {
      lVar11 = 0x4b0;
      if (*(uint *)(**(long **)(*plVar5 + 0xa8) + 0x10) < 0x1f) {
        lVar11 = 0;
      }
      lVar11 = *(long *)(*(long *)(**(long **)(*plVar5 + 0xa8) + 0x18) + lVar11 + 0x20);
      if ((lVar11 != 0) && (*(long *)(lVar11 + 0x28) != 0)) {
        if (*(uint *)(lVar11 + 0x20) <= uVar10) {
          uVar10 = 0;
        }
        uVar10 = *(uint *)(*(long *)(lVar11 + 0x28) + (ulong)uVar10 * 0x40 + 0x18);
        if (uVar10 != 0) {
          lVar11 = FUN_7101512540(*DAT_7103a59ec8);
          uVar9 = FUN_710150aeb0(lVar11,(long)&local_40,uVar10);
          if (((uVar9 & 1) != 0) && (bVar6 = FUN_7101508674((long)&local_40), bVar6)) {
            return 1;
          }
        }
      }
    }
    if (((*(long *)(param_1 + 8) != 0) &&
        (lVar11 = FUN_710150f7dc(*(long *)(param_1 + 8)), lVar11 != 0)) &&
       (uVar10 = *(uint *)(lVar11 + 0x28), uVar10 != 0)) {
      lVar11 = FUN_7101512540(*DAT_7103a59ec8);
      uVar9 = FUN_710150aeb0(lVar11,(long)&local_40,uVar10);
      if (((uVar9 & 1) != 0) && (bVar6 = FUN_7101508674((long)&local_40), bVar6)) {
        return 1;
      }
    }
  }
  return 0;
}



undefined8
FUN_710150ea58(undefined8 param_1,undefined8 param_2,long *param_3,uint param_4,undefined8 param_5,
              undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined8 param_9)

{
  FUN_7100bc08f0(param_3,"%s_%02d",param_1,(ulong)(param_4 & ((int)param_4 >> 0x1f ^ 0xffffffffU)),
                 param_6,param_7,param_8,param_9);
  return 1;
}



void FUN_710150ea90(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710150ead0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00710150ed58)

void FUN_710150eaf0(long param_1,long *param_2)

{
  uint *puVar1;
  long *plVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  char cVar9;
  undefined2 uVar10;
  byte *pbVar11;
  uint *puVar12;
  bool bVar13;
  uint uVar14;
  long lVar15;
  long *plVar16;
  long lVar17;
  undefined4 *puVar18;
  long *plVar19;
  int iVar20;
  undefined4 *puVar21;
  undefined8 uVar22;
  ulong uVar23;
  uint uVar24;
  long lVar25;
  ulong uVar26;
  undefined8 *puVar27;
  undefined1 auVar28 [16];
  long local_290;
  undefined8 local_288;
  undefined1 *local_280;
  undefined8 ****ppppuStack_278;
  undefined8 ****local_270;
  undefined8 ***local_268 [4];
  undefined8 **local_248 [4];
  undefined8 *local_228 [4];
  undefined8 local_208 [4];
  undefined1 local_1e8 [32];
  undefined8 local_1c8;
  undefined4 local_1c0;
  undefined4 local_1b8;
  undefined4 local_1b0;
  undefined1 local_1ac;
  byte *local_1a8;
  uint *puStack_1a0;
  undefined8 local_198;
  undefined2 local_190;
  byte *local_188;
  undefined8 local_180;
  ulong local_178;
  undefined2 local_170;
  undefined1 local_7d;
  undefined8 local_78;
  undefined4 local_70;
  undefined1 local_6c;
  
  plVar19 = DAT_7103a65db8;
  lVar25 = *DAT_7103a65db8;
  if (lVar25 == 0) {
    lVar25 = FUN_71005fbcb0(8,0x640);
joined_r0x00710150ec28:
    if (lVar25 != 0) {
      *(long *)(param_1 + 0x58) = lVar25;
      *(undefined4 *)(param_1 + 0x50) = 400;
    }
  }
  else {
    plVar16 = param_2;
    if (param_2 != (long *)0x0) {
LAB_710150eb5c:
      lVar25 = (**(code **)(*plVar16 + 0x30))(plVar16,0x640,8);
      goto joined_r0x00710150ec28;
    }
    lVar15 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
    plVar16 = (long *)(lVar25 + 8);
    if (lVar15 != 0) {
      plVar16 = (long *)(lVar15 + 0x88);
    }
    plVar16 = (long *)*plVar16;
    if (plVar16 != (long *)0x0) goto LAB_710150eb5c;
  }
  lVar25 = 0x4d8;
  if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x20) {
    lVar25 = 0;
  }
  lVar25 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar25 + 0x20);
  uVar24 = *(uint *)(lVar25 + 0x20);
  uVar26 = (ulong)uVar24;
  if (0 < (int)uVar24) {
    lVar15 = *plVar19;
    if (lVar15 == 0) {
      lVar15 = FUN_71005fbcb0(8,uVar26 * 0x28);
joined_r0x00710150ec3c:
      if (lVar15 != 0) {
        uVar14 = uVar24 - 1;
        *(long *)(param_1 + 0x28) = lVar15;
        if (1 < uVar24) {
          if (uVar14 == 1) {
            uVar23 = 0;
          }
          else {
            uVar23 = 0;
            plVar16 = (long *)(lVar15 + 0x20);
            do {
              uVar23 = uVar23 + 2;
              plVar16[-4] = (long)plVar16;
              *plVar16 = (long)(plVar16 + 4);
              plVar16 = plVar16 + 8;
            } while (((ulong)uVar14 & 0xfffffffe) != uVar23);
          }
          if ((uVar14 & 1) != 0) {
            plVar16 = (long *)(lVar15 + uVar23 * 0x20);
            *plVar16 = (long)(plVar16 + 4);
          }
        }
        *(undefined8 *)(lVar15 + (long)(int)(uVar14 * 4) * 8) = 0;
        lVar17 = lVar15 + uVar26 * 0x20;
        *(long *)(param_1 + 0x30) = lVar15;
        if (lVar17 != 0) {
          *(long *)(param_1 + 0x20) = lVar17;
          *(undefined4 *)(param_1 + 0x18) = 0;
          *(uint *)(param_1 + 0x1c) = uVar24;
        }
      }
      lVar15 = *plVar19;
      if (lVar15 == 0) goto LAB_710150ed28;
      plVar16 = param_2;
      if (param_2 == (long *)0x0) {
LAB_710150ece0:
        lVar17 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
        plVar2 = (long *)(lVar15 + 8);
        if (lVar17 != 0) {
          plVar2 = (long *)(lVar17 + 0x88);
        }
        plVar16 = (long *)*plVar2;
        if ((long *)*plVar2 == (long *)0x0) goto LAB_710150ed64;
      }
      puVar18 = (undefined4 *)(**(code **)(*plVar16 + 0x30))(plVar16,uVar26 << 5,8);
    }
    else {
      plVar16 = param_2;
      if (param_2 != (long *)0x0) {
LAB_710150ec00:
        lVar15 = (**(code **)(*plVar16 + 0x30))(plVar16,uVar26 * 0x28,8);
        goto joined_r0x00710150ec3c;
      }
      lVar17 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      plVar16 = (long *)(lVar15 + 8);
      if (lVar17 != 0) {
        plVar16 = (long *)(lVar17 + 0x88);
      }
      plVar16 = (long *)*plVar16;
      if (plVar16 != (long *)0x0) goto LAB_710150ec00;
      lVar15 = *plVar19;
      if (lVar15 != 0) goto LAB_710150ece0;
LAB_710150ed28:
      puVar18 = (undefined4 *)FUN_71005fbcb0(8,uVar26 << 5);
    }
    if (puVar18 != (undefined4 *)0x0) {
      lVar15 = uVar26 << 1;
      puVar21 = puVar18;
      do {
        *puVar21 = 0;
        lVar15 = lVar15 + -2;
        puVar21[4] = 0;
        puVar21 = puVar21 + 8;
      } while (lVar15 != 0);
      *(undefined4 **)(param_1 + 0x38) = puVar18;
      *(undefined4 *)(param_1 + 0x40) = 0;
      *(undefined4 *)(param_1 + 0x44) = 0;
    }
  }
LAB_710150ed64:
  local_288 = 0;
  ppppuStack_278 = local_268;
  local_268[0] = local_248;
  local_248[0] = local_228;
  local_228[0] = local_208;
  local_280 = (undefined1 *)0x0;
  local_208[0] = 0;
  if (local_1e8 != (undefined1 *)0x0) {
    local_288 = 0x400000000;
    local_280 = local_1e8;
  }
  local_1ac = 0;
  local_1c0 = 2;
  local_1c8 = 0xffffffff;
  local_1b8 = 0xffffffff;
  local_1b0 = 0xffffffff;
  local_178 = 0xffffffff00000000;
  local_170 = 0;
  local_188 = (byte *)0x0;
  local_180 = (uint *)0x0;
  local_290 = lVar25;
  local_270 = ppppuStack_278;
  FUN_710290da90(&local_188,&local_290,0);
  puVar12 = local_180;
  pbVar11 = local_188;
  local_190 = local_170;
  uVar10 = local_190;
  local_1a8 = local_188;
  puStack_1a0 = local_180;
  local_198 = local_178;
  uVar26 = local_198;
  local_190._1_1_ = (char)((ushort)local_170 >> 8);
  bVar13 = local_190._1_1_ == '\0';
  local_190 = uVar10;
  if (bVar13) {
    local_190._0_1_ = (char)local_170;
    cVar9 = (char)local_190;
    bVar13 = (char)local_190 == '\0';
    local_198._4_4_ = (int)(local_178 >> 0x20);
    iVar8 = local_198._4_4_;
    local_198 = uVar26;
    iVar6 = -1;
    if (bVar13) {
      iVar6 = 1;
    }
    do {
      uVar24 = (uint)local_198;
      if (puVar12 == (uint *)0x0) {
        puVar27 = (undefined8 *)
                  (**(code **)(**(long **)pbVar11 + 0x80))(*(long **)pbVar11,local_198 & 0xffffffff)
        ;
      }
      else {
        uVar14 = (uint)local_198;
        if (*puVar12 <= (uint)local_198) {
          uVar14 = 0;
        }
        puVar27 = *(undefined8 **)(*(long *)(puVar12 + 2) + (long)(int)uVar14 * 8);
      }
      local_7d = 0;
      uVar26 = (ulong)local_180 >> 0x20;
      local_180 = (uint *)CONCAT44((uint)uVar26 & 0xffffff00,0x100);
      local_188 = (byte *)((long)&local_180 + 4);
      FUN_710290e160(puVar27,&local_188);
      local_188[(long)(int)local_180 + -1] = 0;
      uVar14 = FUN_7100bb2120(local_188,0);
      if (*(int *)(param_1 + 0x18) < *(int *)(param_1 + 0x1c)) {
        plVar19 = *(long **)(param_1 + 0x28);
        if (plVar19 != (long *)0x0) {
          *(long *)(param_1 + 0x28) = *plVar19;
        }
        local_188[(long)(int)local_180 + -1] = 0;
        FUN_7100bbc600(plVar19,param_2,&local_188,8);
        *(uint *)(plVar19 + 2) = uVar14;
        *(undefined8 *)((long)plVar19 + 0x14) = 0xffffffffffffffff;
        *(undefined4 *)((long)plVar19 + 0x1c) = 0xffffffff;
        if (*(int *)(puVar27 + 6) == 0) {
          iVar20 = *(int *)((long)puVar27 + 0x2c);
          if (399 < iVar20) {
            iVar20 = -1;
          }
          *(int *)((long)plVar19 + 0x14) = iVar20;
        }
        local_78._0_5_ = 0;
        local_78._5_3_ = 0;
        local_70 = 0;
        local_6c = 0;
        if ((*(char *)((long)puVar27 + 0x24) == -0x3c) || (*(char *)((long)puVar27 + 0x24) == -0x3f)
           ) {
          local_78._0_5_ = (undefined5)puVar27[3];
          uVar22 = *(undefined8 *)((long)puVar27 + 0x1d);
          local_78._5_3_ = (undefined3)uVar22;
          local_70 = (undefined4)((ulong)uVar22 >> 0x18);
          local_6c = (undefined1)((ulong)uVar22 >> 0x38);
        }
        auVar28 = FUN_7102813520(&local_78,"CoordinateAttributeRef");
        uVar4 = auVar28._12_4_ & 0xff;
        if (((uVar4 == 0xd3) || ((uVar4 == 0xd1 && (-1 < auVar28._8_4_)))) && (auVar28._8_4_ != 0))
        {
          lVar25 = 0x488;
          if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1e) {
            lVar25 = 0;
          }
          lVar15 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar25 + 0x20);
          lVar25 = FUN_7101f42580(lVar15,auVar28._8_8_);
          if (lVar25 != 0) {
            iVar20 = (int)((ulong)(lVar25 - *(long *)(lVar15 + 0x28)) >> 5);
            if (iVar20 < 0) {
              iVar20 = -1;
            }
            else if (*(int *)(lVar15 + 0x20) <= iVar20) {
              iVar20 = -1;
            }
            *(int *)(plVar19 + 3) = iVar20;
          }
        }
        local_78._0_5_ = 0;
        local_78._5_3_ = 0;
        local_70 = 0;
        local_6c = 0;
        if ((*(char *)((long)puVar27 + 0x24) == -0x3c) || (*(char *)((long)puVar27 + 0x24) == -0x3f)
           ) {
          local_78._0_5_ = (undefined5)puVar27[3];
          uVar22 = *(undefined8 *)((long)puVar27 + 0x1d);
          local_78._5_3_ = (undefined3)uVar22;
          local_70 = (undefined4)((ulong)uVar22 >> 0x18);
          local_6c = (undefined1)((ulong)uVar22 >> 0x38);
        }
        auVar28 = FUN_7102813520(&local_78,"CoordinateClothInfoRef");
        uVar4 = auVar28._12_4_ & 0xff;
        if (((uVar4 == 0xd3) || ((uVar4 == 0xd1 && (-1 < auVar28._8_4_)))) && (auVar28._8_4_ != 0))
        {
          lVar25 = 0x4b0;
          if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1f) {
            lVar25 = 0;
          }
          lVar15 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar25 + 0x20);
          lVar25 = FUN_7101f44600(lVar15,auVar28._8_8_);
          if (lVar25 != 0) {
            iVar20 = (int)((ulong)(lVar25 - *(long *)(lVar15 + 0x28)) >> 6);
            if (iVar20 < 0) {
              iVar20 = -1;
            }
            else if (*(int *)(lVar15 + 0x20) <= iVar20) {
              iVar20 = -1;
            }
            *(int *)((long)plVar19 + 0x1c) = iVar20;
          }
        }
        if (*(int *)(param_1 + 0x18) < *(int *)(param_1 + 0x1c)) {
          *(long **)(*(long *)(param_1 + 0x20) + (long)*(int *)(param_1 + 0x18) * 8) = plVar19;
          *(int *)(param_1 + 0x18) = *(int *)(param_1 + 0x18) + 1;
        }
      }
      else {
        plVar19 = (long *)0x0;
      }
      if (uVar14 != 0) {
        uVar4 = *(uint *)(param_1 + 0x44);
        uVar3 = 0;
        if (uVar4 != 0) {
          uVar3 = uVar14 / uVar4;
        }
        uVar3 = uVar14 - uVar3 * uVar4;
        uVar7 = uVar3;
        do {
          uVar5 = *(uint *)(*(long *)(param_1 + 0x38) +
                           (-(ulong)(uVar7 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar7 << 4));
          if (uVar5 == 0) {
            puVar1 = (uint *)(*(long *)(param_1 + 0x38) + (long)(int)uVar7 * 0x10);
            *puVar1 = uVar14;
            *(long **)(puVar1 + 2) = plVar19;
            *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
            break;
          }
          if (uVar5 == uVar14) break;
          uVar5 = 0;
          if ((int)(uVar7 + 1) < (int)uVar4) {
            uVar5 = uVar7 + 1;
          }
          uVar7 = uVar5;
        } while (uVar5 != uVar3);
      }
      uVar14 = *(uint *)((long)plVar19 + 0x14);
      plVar19 = DAT_7103a65db8;
      if ((-1 < (int)uVar14) && ((int)uVar14 < *(int *)(param_1 + 0x50))) {
        *(undefined4 *)(*(long *)(param_1 + 0x58) + (ulong)uVar14 * 4) =
             *(undefined4 *)(puVar27 + 5);
        plVar19 = DAT_7103a65db8;
      }
      do {
        uVar24 = iVar6 + uVar24;
        local_198 = CONCAT44(local_198._4_4_,uVar24);
        if (cVar9 == '\0') {
          if (iVar8 < (int)uVar24) goto LAB_710150ee08;
        }
        else if ((int)uVar24 < iVar8) goto LAB_710150ee08;
        uVar14 = FUN_710290dcb0(&local_1a8);
      } while ((uVar14 & 1) == 0);
    } while( true );
  }
LAB_710150ee08:
  if (0 < (int)local_288) {
    lVar25 = 0;
    do {
      (**(code **)(**(long **)(local_280 + lVar25 * 8) + 0x18))();
      lVar25 = lVar25 + 1;
    } while (lVar25 < (int)local_288);
  }
  lVar25 = *plVar19;
  if (lVar25 == 0) {
    plVar19 = (long *)FUN_71005fbcb0(8,0x20);
  }
  else {
    plVar19 = param_2;
    if (param_2 == (long *)0x0) {
      lVar15 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      plVar19 = (long *)(lVar25 + 8);
      if (lVar15 != 0) {
        plVar19 = (long *)(lVar15 + 0x88);
      }
      plVar19 = (long *)*plVar19;
      if (plVar19 == (long *)0x0) {
        plVar19 = (long *)0x0;
        goto LAB_710150f258;
      }
    }
    plVar19 = (long *)(**(code **)(*plVar19 + 0x30))(plVar19,0x20,8);
  }
LAB_710150f258:
  local_188 = &DAT_71030e70e0;
  FUN_7100bbc600(plVar19,param_2,&local_188,8);
  plVar19[2] = -0x419621b7;
  plVar19[3] = -1;
  *(long **)(param_1 + 0x48) = plVar19;
  uVar24 = *(uint *)(param_1 + 0x44);
  uVar14 = 0;
  if (uVar24 != 0) {
    uVar14 = 0xbe69de49 / uVar24;
  }
  uVar14 = 0xbe69de49 - uVar14 * uVar24;
  uVar4 = uVar14;
  while( true ) {
    iVar6 = *(int *)(*(long *)(param_1 + 0x38) +
                    (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
    if (iVar6 == -0x419621b7) {
      return;
    }
    if (iVar6 == 0) break;
    uVar3 = 0;
    if ((int)(uVar4 + 1) < (int)uVar24) {
      uVar3 = uVar4 + 1;
    }
    uVar4 = uVar3;
    if (uVar3 == uVar14) {
      return;
    }
  }
  puVar18 = (undefined4 *)(*(long *)(param_1 + 0x38) + (long)(int)uVar4 * 0x10);
  *puVar18 = 0xbe69de49;
  *(undefined8 *)(puVar18 + 2) = *(undefined8 *)(param_1 + 0x48);
  *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
  return;
}



undefined4 FUN_710150f560(long param_1,uint param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  long lVar6;
  ulong uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  long lVar11;
  float fVar12;
  
  thunk_EXT_FUN_02e95df0();
  uVar1 = *(uint *)(param_1 + 0x18);
  if ((int)uVar1 < 1) {
    uVar2 = 0;
  }
  else {
    uVar9 = (param_2 ^ param_2 >> 0x1e) * 0x6c078965 + 1;
    fVar12 = 0.0;
    uVar2 = 0;
    uVar7 = 0;
    uVar8 = (uVar9 ^ uVar9 >> 0x1e) * 0x6c078965 + 2;
    uVar3 = (uVar8 ^ uVar8 >> 0x1e) * 0x6c078965 + 3;
    uVar10 = (uVar3 ^ uVar3 >> 0x1e) * 0x6c078965 + 4;
    do {
      uVar5 = uVar10;
      if (((uVar7 < uVar1) &&
          (lVar11 = *(long *)(*(long *)(param_1 + 0x20) + uVar7 * 8), lVar11 != 0)) &&
         (uVar4 = *(uint *)(lVar11 + 0x18), -1 < (int)uVar4)) {
        lVar6 = 0x488;
        if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1e) {
          lVar6 = 0;
        }
        lVar6 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar6 + 0x20);
        if (lVar6 != 0) {
          if (uVar4 < *(uint *)(lVar6 + 0x20)) {
            lVar6 = *(long *)(lVar6 + 0x28);
          }
          else {
            uVar4 = 0;
            lVar6 = *(long *)(lVar6 + 0x28);
          }
          if ((((lVar6 != 0) &&
               (lVar6 = lVar6 + (ulong)uVar4 * 0x20, *(char *)(lVar6 + 0x1a) == '\0')) &&
              ((*(int *)(lVar6 + 8) == 0 && (fVar12 = fVar12 + 1.0, ABS(fVar12) != INFINITY)))) &&
             ((fVar12 < 0.0 ||
              (uVar9 = uVar9 ^ uVar9 << 0xb, uVar5 = uVar9 >> 8 ^ uVar10 >> 0x13 ^ uVar9 ^ uVar10,
              uVar9 = uVar8, uVar8 = uVar3, uVar3 = uVar10,
              fVar12 * ((float)(uVar5 >> 9 | 0x3f800000) + -1.0) + 0.0 < 1.0)))) {
            uVar2 = *(undefined4 *)(lVar11 + 0x10);
          }
        }
      }
      uVar10 = uVar5;
      uVar7 = uVar7 + 1;
    } while (uVar1 != uVar7);
  }
  return uVar2;
}



void FUN_710150f720(long param_1,undefined8 param_2)

{
  uint uVar1;
  bool bVar2;
  ulong uVar3;
  ulong uVar4;
  undefined8 *local_140;
  undefined8 local_138;
  long local_40;
  undefined8 local_38;
  
  local_140 = &DAT_7103959ed0;
  local_40 = DAT_7103a61990 + 0x10;
  local_38 = 0;
  uVar1 = *(uint *)(param_1 + 0x18);
  local_138 = param_2;
  if (0 < (int)uVar1) {
    uVar4 = 0;
    do {
      if (uVar4 < *(uint *)(param_1 + 0x18)) {
        local_38 = *(undefined8 *)(*(long *)(param_1 + 0x20) + uVar4 * 8);
      }
      else {
        local_38 = 0;
      }
      uVar3 = (*(code *)*local_140)(&local_140,&local_40);
    } while (((uVar3 & 1) == 0) && (bVar2 = (ulong)uVar1 - 1 != uVar4, uVar4 = uVar4 + 1, bVar2));
  }
  (*(code *)local_140[3])(&local_140);
  return;
}



long FUN_710150f7dc(long param_1)

{
  uint uVar1;
  long lVar2;
  
  uVar1 = *(uint *)(param_1 + 0x1c);
  if (-1 < (int)uVar1) {
    lVar2 = 0x4b0;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1f) {
      lVar2 = 0;
    }
    lVar2 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar2 + 0x20);
    if (lVar2 != 0) {
      if (*(uint *)(lVar2 + 0x20) <= uVar1) {
        uVar1 = 0;
      }
      return *(long *)(lVar2 + 0x28) + (ulong)uVar1 * 0x40;
    }
  }
  return 0;
}



undefined8 FUN_710150f838(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a619a8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a619a8), iVar1 != 0))
  {
    *DAT_7103a619a0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a619a8);
  }
  if (param_2 != DAT_7103a619a0) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_710150f938(void)

{
  int iVar1;
  
  if (((*DAT_7103a619a8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a619a8), iVar1 != 0))
  {
    *DAT_7103a619a0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a619a8);
  }
  return DAT_7103a619a0;
}



void FUN_710150f998(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710150f9d8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 FUN_710150f9f8(long param_1)

{
  (**(code **)**(undefined8 **)(param_1 + 8))();
  return 0;
}



void FUN_710150fa40(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710150fa80. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_710150faa4(undefined8 *param_1)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  
  *param_1 = &DAT_710395ad40;
  if (DAT_7104078e50 == param_1) {
    DAT_7104078e50 = (undefined8 *)0x0;
    (**(code **)*DAT_710407a3f8)();
    DAT_710407a3f8 = (undefined8 *)0x0;
  }
  lVar2 = param_1[1];
  *param_1 = &DAT_7103a07950;
  if (lVar2 != 0) {
    if (lVar2 == 1) {
      return;
    }
    if ((*(uint *)(lVar2 + 200) & 1) == 0) {
      lVar3 = 0;
    }
    else {
      lVar3 = lVar2 + 0x88;
      thunk_EXT_FUN_02e95df0(lVar2 + 0xa8);
    }
    plVar1 = (long *)((long)*(int *)(lVar2 + 0x7c) + (long)param_1);
    if (*plVar1 != 0) {
      *(long *)(*plVar1 + 8) = plVar1[1];
    }
    if ((long *)plVar1[1] != (long *)0x0) {
      *(long *)plVar1[1] = *plVar1;
    }
    *plVar1 = 0;
    plVar1[1] = 0;
    *(int *)(lVar2 + 0x78) = *(int *)(lVar2 + 0x78) + -1;
    if (lVar3 != 0) {
      thunk_EXT_FUN_02e95df0(lVar3 + 0x20);
    }
  }
  param_1[1] = 1;
  return;
}



void FUN_710150fb88(undefined8 *param_1)

{
  long *plVar1;
  
  FUN_710150faa4(param_1);
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710150fbcc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_710150fbf0(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710150fc30. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710150fc50(undefined8 param_1,long *param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  undefined *puVar2;
  int *piVar3;
  long lVar4;
  undefined *puVar5;
  long *plVar6;
  
  plVar6 = (long *)0x0;
  switch(param_3) {
  case 0:
    plVar6 = (long *)FUN_71024d4670(0xa0,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    lVar4 = DAT_7103a616a8;
    goto LAB_7101511604;
  case 1:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b2d0;
    break;
  case 2:
    plVar6 = (long *)FUN_71024d4670(0xa0,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    lVar4 = DAT_7103a62c60;
    goto LAB_7101511604;
  case 3:
    plVar6 = (long *)FUN_71024d4670(0x118,param_2,8);
    thunk_EXT_FUN_02e95df0(plVar6 + 1,0,0x108);
    lVar4 = DAT_7103a61978;
    plVar6[0x22] = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[6] = 0;
    plVar6[7] = 0;
    plVar6[0x20] = 0;
    *(undefined4 *)(plVar6 + 0x21) = 0;
    *plVar6 = lVar4 + 0x10;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    plVar6[0x10] = 0;
    plVar6[0x11] = 0;
    plVar6[0x12] = 0;
    plVar6[0x13] = 0;
    plVar6[0x14] = 0;
    plVar6[0x15] = 0;
    plVar6[0x16] = 0;
    plVar6[0x17] = 0;
    plVar6[0x18] = 0;
    plVar6[0x19] = 0;
    plVar6[0x1a] = 0;
    plVar6[0x1b] = 0;
    plVar6[0x1c] = 0;
    plVar6[0x1d] = 0;
    plVar6[0x1e] = 0;
    plVar6[0x1f] = 0;
    return plVar6;
  case 4:
    plVar6 = (long *)FUN_71024d4670(0x60,param_2,8);
    lVar4 = DAT_7103a61998;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    puVar2 = (undefined *)(lVar4 + 0x10);
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 10) = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[6] = 0;
    plVar6[7] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    goto LAB_71015119f0;
  case 5:
    plVar6 = (long *)FUN_71024d4670(0x90,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    lVar4 = DAT_7103a62c70;
    goto LAB_71015110cc;
  case 6:
    plVar6 = (long *)FUN_71024d4670(0x38,param_2,8);
    *(undefined4 *)(plVar6 + 2) = 0;
    lVar4 = DAT_7103a62c78;
    puVar5 = &DAT_710395e318;
    *(undefined1 *)((long)plVar6 + 0x14) = 0;
    goto LAB_7101511354;
  case 7:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395ae08;
    break;
  case 8:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395ae90;
    break;
  case 9:
    plVar6 = (long *)FUN_71024d4670(0x38,param_2,8);
    lVar4 = DAT_7103a62c80;
    plVar6[5] = 0;
    plVar6[6] = 0;
    puVar2 = (undefined *)(lVar4 + 0x10);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[4] = 0;
    *(undefined4 *)(plVar6 + 5) = 0;
    goto LAB_71015119f0;
  case 10:
    plVar6 = (long *)FUN_71024d4670(0x4518,param_2,8);
    thunk_EXT_FUN_02e95df0(plVar6,0,0x4518);
    FUN_7101511a0c(plVar6);
    return plVar6;
  case 0xb:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395af18;
    break;
  case 0xc:
    plVar6 = (long *)FUN_71024d4670(0xa8,param_2,8);
    plVar6[6] = 0;
    plVar6[7] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    plVar6[0x10] = 0;
    plVar6[0x11] = 0;
    lVar4 = DAT_7103a62c90 + 0x10;
    plVar6[0x14] = 0;
    *plVar6 = lVar4;
    plVar6[1] = 0;
    plVar6[0x10] = (long)&DAT_710395e370;
    plVar6[0x12] = 0;
    plVar6[0x13] = 0;
    return plVar6;
  case 0xd:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395afa0;
    break;
  case 0xe:
    plVar6 = (long *)FUN_71024d4670(0x698,param_2,8);
    thunk_EXT_FUN_02e95df0(plVar6 + 1,0,0x690);
    *plVar6 = DAT_7103a61930 + 0x10;
    FUN_7101515888(plVar6 + 6);
    *(undefined4 *)(plVar6 + 0xd2) = 0;
    return plVar6;
  case 0xf:
    plVar6 = (long *)FUN_71024d4670(0x38,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    puVar2 = (undefined *)(DAT_7103a62c98 + 0x10);
    goto LAB_71015119f0;
  case 0x10:
    plVar6 = (long *)FUN_71024d4670(0x30,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    puVar2 = (undefined *)(DAT_7103a61950 + 0x10);
    goto LAB_71015119f0;
  case 0x11:
    plVar6 = (long *)FUN_71024d4670(0x90,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    lVar4 = DAT_7103a62c68;
    goto LAB_71015110cc;
  case 0x12:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395ad80;
    break;
  case 0x13:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b3e0;
    break;
  case 0x14:
    plVar6 = (long *)FUN_71024d4670(0xa0,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    lVar4 = DAT_7103a62ca0;
    goto LAB_7101511604;
  case 0x15:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395cf78;
    break;
  case 0x16:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d000;
    break;
  case 0x17:
    lVar4 = *DAT_7103a71180;
    piVar3 = DAT_7103a65e48;
    if ((lVar4 != 0) && (*(char *)(lVar4 + 0x40) != '\0')) {
      piVar3 = (int *)(lVar4 + 0x10);
    }
    if (*piVar3 != 0x7fffffff) {
      return (long *)0x0;
    }
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395e250;
    plVar6[2] = 0;
    plVar6[3] = 0;
    break;
  case 0x18:
    lVar4 = *DAT_7103a71180;
    piVar3 = DAT_7103a65e48;
    if ((lVar4 != 0) && (*(char *)(lVar4 + 0x40) != '\0')) {
      piVar3 = (int *)(lVar4 + 0x10);
    }
    if (*piVar3 != 0x7fffffff) {
      return (long *)0x0;
    }
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395e1c8;
    break;
  case 0x19:
    plVar6 = (long *)FUN_71024d4670(0x798,param_2,8);
    thunk_EXT_FUN_02e95df0(plVar6,0,0x798);
    FUN_7101511c0c(plVar6);
    return plVar6;
  case 0x1a:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d5a8;
    break;
  case 0x1b:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395bf00;
    break;
  case 0x1c:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b028;
    break;
  case 0x1d:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395bbd8;
    break;
  case 0x1e:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    puVar2 = (undefined *)(DAT_7103a62d28 + 0x10);
    goto LAB_71015119f0;
  case 0x1f:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395bc60;
    break;
  case 0x20:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395bce8;
    break;
  case 0x21:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c098;
    break;
  case 0x22:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c120;
    break;
  case 0x23:
    plVar6 = (long *)FUN_71024d4670(0x14e0,param_2,8);
    thunk_EXT_FUN_02e95df0(plVar6,0,0x14e0);
    FUN_7101511e60(plVar6);
    return plVar6;
  case 0x24:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b1c0;
    break;
  case 0x25:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b138;
    break;
  case 0x26:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b0b0;
    break;
  case 0x27:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b248;
    break;
  case 0x28:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b358;
    break;
  case 0x29:
    plVar6 = (long *)FUN_71024d4670(0x90,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    lVar4 = DAT_7103a617e8;
    goto LAB_71015110cc;
  case 0x2a:
    plVar6 = (long *)FUN_71024d4670(0x98,param_2,8);
    *plVar6 = 0;
    plVar6[1] = 0;
    plVar6[0x12] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[6] = 0;
    plVar6[7] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    plVar6[0x10] = 0;
    plVar6[0x11] = 0;
    FUN_7101511f00(plVar6);
    return plVar6;
  case 0x2b:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b468;
    break;
  case 0x2c:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b4f0;
    break;
  case 0x2d:
    plVar6 = (long *)FUN_71024d4670(0xa0,param_2,8);
    plVar6[6] = 0;
    plVar6[7] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    lVar4 = DAT_7103a62cb0 + 0x10;
    plVar6[0x10] = 0;
    plVar6[0x11] = 0;
    *plVar6 = lVar4;
    plVar6[1] = 0;
    plVar6[0x12] = 0;
    plVar6[0x13] = 0;
    *(undefined4 *)(plVar6 + 0x12) = 0;
    plVar6[0x10] = 0;
    plVar6[0x11] = 0;
    return plVar6;
  case 0x2e:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b578;
    break;
  case 0x2f:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b600;
    break;
  case 0x30:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b688;
    break;
  case 0x31:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b710;
    break;
  case 0x32:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b798;
    break;
  case 0x33:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b820;
    break;
  case 0x34:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b8a8;
    break;
  case 0x35:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b930;
    break;
  case 0x36:
    plVar6 = (long *)FUN_71024d4670(0x5270,param_2,8);
    thunk_EXT_FUN_02e95df0(plVar6,0,0x5270);
    FUN_7101511f60(plVar6);
    return plVar6;
  case 0x37:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395b9b8;
    break;
  case 0x38:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395ba40;
    break;
  case 0x39:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395bac8;
    break;
  case 0x3a:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395dda0;
    break;
  case 0x3b:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    puVar2 = (undefined *)(DAT_7103a62cb8 + 0x10);
    goto LAB_71015119f0;
  case 0x3c:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395bb50;
    break;
  default:
    goto switchD_710150fc80_caseD_3d;
  case 0x3e:
    plVar6 = (long *)FUN_71024d4670(0x6098,param_2,8);
    thunk_EXT_FUN_02e95df0(plVar6,0,0x6098);
    FUN_71015121c0(plVar6);
    return plVar6;
  case 0x3f:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    puVar2 = (undefined *)(DAT_7103a62cd0 + 0x10);
    goto LAB_71015119f0;
  case 0x40:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395bd70;
    break;
  case 0x41:
    plVar6 = (long *)FUN_71024d4670(0xe768,param_2,8);
    thunk_EXT_FUN_02e95df0(plVar6,0,0xe768);
    FUN_7101512250(plVar6);
    return plVar6;
  case 0x42:
    plVar6 = (long *)FUN_71024d4670(0xc3f8,param_2,8);
    thunk_EXT_FUN_02e95df0(plVar6 + 1,0,0xc3f0);
    *plVar6 = DAT_7103a61780 + 0x10;
    lVar4 = 0x28;
    do {
      puVar1 = (undefined4 *)((long)plVar6 + lVar4);
      lVar4 = lVar4 + 0x360;
      *puVar1 = 0;
      puVar1[0x18] = 0;
      puVar1[0x30] = 0;
      puVar1[0x48] = 0;
      puVar1[0x60] = 0;
      puVar1[0x78] = 0;
      puVar1[0x90] = 0;
      puVar1[0xa8] = 0;
      puVar1[0xc0] = 0;
    } while ((long *)(puVar1 + 0xd8) != plVar6 + 0x187d);
    *(undefined4 *)(plVar6 + 0x187d) = 0;
    *(undefined1 *)((long)plVar6 + 0xc3ec) = 0;
    *(undefined4 *)(plVar6 + 0x187e) = 0;
    plVar6[3] = (long)(plVar6 + 5);
    plVar6[4] = 0x20a00000000;
    return plVar6;
  case 0x43:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    puVar2 = (undefined *)(DAT_7103a62cc0 + 0x10);
    goto LAB_71015119f0;
  case 0x44:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395be78;
    break;
  case 0x45:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395bf88;
    break;
  case 0x46:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c010;
    break;
  case 0x47:
    plVar6 = (long *)FUN_71024d4670(0x38,param_2,8);
    *(undefined4 *)(plVar6 + 2) = 0;
    lVar4 = DAT_7103a62cd8;
    *(undefined1 *)((long)plVar6 + 0x14) = 0;
    puVar5 = &DAT_710395e2d8;
LAB_7101511354:
    puVar2 = (undefined *)(lVar4 + 0x10);
    plVar6[4] = (long)puVar5;
    plVar6[5] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 6) = 0;
    goto LAB_71015119f0;
  case 0x48:
    plVar6 = (long *)FUN_71024d4670(0xf8,param_2,8);
    plVar6[3] = 0;
    plVar6[4] = (long)&DAT_710395e2f8;
    lVar4 = DAT_7103a62ce0;
    *(undefined4 *)(plVar6 + 2) = 0;
    *(undefined1 *)((long)plVar6 + 0x14) = 0;
    plVar6[5] = 0;
    *(undefined4 *)(plVar6 + 6) = 0;
    plVar6[7] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    *plVar6 = lVar4 + 0x10;
    plVar6[1] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    plVar6[0x10] = 0;
    plVar6[0x11] = 0;
    plVar6[0x12] = 0;
    plVar6[0x13] = 0;
    plVar6[0x14] = 0;
    plVar6[0x15] = 0;
    plVar6[0x16] = 0;
    plVar6[0x17] = 0;
    plVar6[0x18] = 0;
    plVar6[0x19] = 0;
    plVar6[0x1a] = 0;
    plVar6[0x1b] = 0;
    plVar6[0x1c] = 0;
    plVar6[0x1d] = 0;
    plVar6[0x1e] = 0;
    return plVar6;
  case 0x49:
    plVar6 = (long *)FUN_71024d4670(0x118,param_2,8);
    lVar4 = DAT_7103a62ce8;
    *(undefined4 *)(plVar6 + 2) = 0;
    plVar6[3] = 0;
    plVar6[4] = (long)&DAT_710395e338;
    *(undefined1 *)((long)plVar6 + 0x14) = 0;
    plVar6[5] = 0;
    *(undefined4 *)(plVar6 + 6) = 0;
    plVar6[7] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    *plVar6 = lVar4 + 0x10;
    plVar6[1] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    plVar6[0x10] = 0;
    plVar6[0x11] = 0;
    plVar6[0x12] = 0;
    plVar6[0x13] = 0;
    plVar6[0x14] = 0;
    plVar6[0x15] = 0;
    plVar6[0x16] = 0;
    plVar6[0x17] = 0;
    plVar6[0x18] = 0;
    plVar6[0x19] = 0;
    plVar6[0x1a] = 0;
    plVar6[0x1b] = 0;
    plVar6[0x1c] = 0;
    plVar6[0x1d] = 0;
    plVar6[0x1e] = 0;
    plVar6[0x1f] = 0;
    plVar6[0x20] = 0;
    plVar6[0x21] = 0;
    plVar6[0x22] = 0;
    return plVar6;
  case 0x4a:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c1a8;
    break;
  case 0x4b:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c230;
    break;
  case 0x4c:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c2b8;
    break;
  case 0x4d:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c340;
    break;
  case 0x4e:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c3c8;
    break;
  case 0x4f:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c450;
    break;
  case 0x50:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c4d8;
    break;
  case 0x51:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c560;
    break;
  case 0x52:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c5e8;
    break;
  case 0x53:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c670;
    break;
  case 0x54:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c6f8;
    break;
  case 0x55:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c780;
    break;
  case 0x56:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c808;
    break;
  case 0x57:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c890;
    break;
  case 0x58:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c918;
    break;
  case 0x59:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395c9a0;
    break;
  case 0x5a:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395ca28;
    break;
  case 0x5b:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395cab0;
    break;
  case 0x5c:
    plVar6 = (long *)FUN_71024d4670(0x68,param_2,8);
    lVar4 = DAT_7103a62cf0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    puVar2 = (undefined *)(lVar4 + 0x10);
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[0xc] = 0;
    plVar6[6] = 0;
    plVar6[7] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    goto LAB_71015119f0;
  case 0x5d:
    plVar6 = (long *)FUN_71024d4670(0x88,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    puVar2 = (undefined *)(DAT_7103a62cf8 + 0x10);
    plVar6[0x10] = 0;
    goto LAB_71015119f0;
  case 0x5e:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395cb38;
    break;
  case 0x5f:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395cbc0;
    break;
  case 0x60:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395cc48;
    break;
  case 0x61:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395ccd0;
    break;
  case 0x62:
    plVar6 = (long *)FUN_71024d4670(0xa0,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    lVar4 = DAT_7103a62d00;
    goto LAB_7101511604;
  case 99:
    plVar6 = (long *)FUN_71024d4670(0xa0,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    lVar4 = DAT_7103a62d08;
    goto LAB_7101511604;
  case 100:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395cd58;
    break;
  case 0x65:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395cde0;
    break;
  case 0x66:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395ce68;
    break;
  case 0x67:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395cef0;
    break;
  case 0x68:
    plVar6 = (long *)FUN_71024d4670(0x90,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    lVar4 = DAT_7103a62d10;
    goto LAB_71015110cc;
  case 0x69:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d088;
    break;
  case 0x6a:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d198;
    break;
  case 0x6b:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d110;
    break;
  case 0x6c:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d220;
    break;
  case 0x6d:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d2a8;
    break;
  case 0x6e:
    plVar6 = (long *)FUN_71024d4670(0x70,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[6] = 0;
    plVar6[7] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    puVar2 = (undefined *)(DAT_7103a618d8 + 0x10);
    goto LAB_71015119f0;
  case 0x6f:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d330;
    break;
  case 0x70:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d3b8;
    break;
  case 0x71:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d440;
    break;
  case 0x72:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d4c8;
    break;
  case 0x73:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d538;
    break;
  case 0x74:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d630;
    break;
  case 0x75:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d6b8;
    break;
  case 0x76:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d740;
    break;
  case 0x77:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d7c8;
    break;
  case 0x78:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d850;
    break;
  case 0x79:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d8d8;
    break;
  case 0x7a:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d9e8;
    break;
  case 0x7b:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395da70;
    break;
  case 0x7c:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395daf8;
    break;
  case 0x7d:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395db80;
    break;
  case 0x7e:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395dc08;
    break;
  case 0x7f:
    plVar6 = (long *)FUN_71024d4670(0xa0,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    lVar4 = DAT_7103a62d18;
LAB_7101511604:
    plVar6[0x10] = 0;
    plVar6[0x11] = 0;
    *plVar6 = lVar4 + 0x10;
    plVar6[1] = 0;
    plVar6[0x12] = 0;
    plVar6[0x13] = 0;
    return plVar6;
  case 0x80:
    plVar6 = (long *)FUN_71024d4670(0x90,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    plVar6[4] = 0;
    plVar6[5] = 0;
    plVar6[8] = 0;
    plVar6[9] = 0;
    plVar6[10] = 0;
    plVar6[0xb] = 0;
    plVar6[0xc] = 0;
    plVar6[0xd] = 0;
    lVar4 = DAT_7103a62d20;
LAB_71015110cc:
    plVar6[0xe] = 0;
    plVar6[0xf] = 0;
    *plVar6 = lVar4 + 0x10;
    plVar6[1] = 0;
    plVar6[0x10] = 0;
    plVar6[0x11] = 0;
    return plVar6;
  case 0x81:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395dc90;
    break;
  case 0x82:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395dd18;
    break;
  case 0x83:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395de28;
    break;
  case 0x84:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395deb0;
    break;
  case 0x85:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395df38;
    break;
  case 0x86:
    plVar6 = (long *)FUN_71024d4670(0x80,param_2,8);
    plVar6[6] = (long)plVar6 + 0x3c;
    plVar6[7] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    *(undefined4 *)(plVar6 + 7) = 0x40;
    puVar2 = &DAT_710395d960;
    break;
  case 0x87:
    plVar6 = (long *)FUN_71024d4670(0x38,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    puVar2 = (undefined *)0x710395dfc0;
    goto LAB_7101510c90;
  case 0x88:
    plVar6 = (long *)FUN_71024d4670(0x38,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    puVar2 = (undefined *)0x710395e028;
    goto LAB_7101510c90;
  case 0x89:
    plVar6 = (long *)FUN_71024d4670(0x38,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    puVar2 = (undefined *)0x710395e090;
    goto LAB_7101510c90;
  case 0x8a:
    plVar6 = (long *)FUN_71024d4670(0x38,param_2,8);
    plVar6[2] = 0;
    plVar6[3] = 0;
    puVar2 = &DAT_710395e0f8;
LAB_7101510c90:
    plVar6[6] = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    goto LAB_71015119f0;
  case 0x8b:
    plVar6 = (long *)FUN_71024d4670(0x38,param_2,8);
    plVar6[6] = 0;
    *plVar6 = (long)&DAT_710395e160;
    plVar6[1] = 0;
    plVar6[2] = 0;
    plVar6[3] = 0;
    plVar6[4] = 0;
    plVar6[5] = 0;
    goto switchD_710150fc80_caseD_3d;
  }
  plVar6[4] = 0;
  plVar6[5] = 0;
  plVar6[8] = 0;
  plVar6[9] = 0;
  plVar6[10] = 0;
  plVar6[0xb] = 0;
  plVar6[0xc] = 0;
  plVar6[0xd] = 0;
  plVar6[0xe] = 0;
  plVar6[0xf] = 0;
LAB_71015119f0:
  *plVar6 = (long)puVar2;
  plVar6[1] = 0;
switchD_710150fc80_caseD_3d:
  return plVar6;
}



void FUN_7101511a0c(long *param_1)

{
  long lVar1;
  long *plVar2;
  
  *(undefined4 *)(param_1 + 2) = 0;
  lVar1 = DAT_7103a62c88;
  *(undefined1 *)((long)param_1 + 0x14) = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[0x843] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *param_1 = lVar1 + 0x10;
  param_1[1] = 0;
  plVar2 = param_1 + 9;
  *plVar2 = (long)(param_1 + 0x3f);
  param_1[0x3f] = (long)(param_1 + 0x75);
  param_1[0x75] = (long)(param_1 + 0xab);
  param_1[0xab] = (long)(param_1 + 0xe1);
  param_1[0xe1] = (long)(param_1 + 0x117);
  param_1[0x117] = (long)(param_1 + 0x14d);
  param_1[0x14d] = (long)(param_1 + 0x183);
  param_1[0x183] = (long)(param_1 + 0x1b9);
  param_1[0x1b9] = (long)(param_1 + 0x1ef);
  param_1[0x1ef] = (long)(param_1 + 0x225);
  param_1[0x225] = (long)(param_1 + 0x25b);
  param_1[7] = (long)plVar2;
  param_1[8] = (long)plVar2;
  param_1[0x25b] = (long)(param_1 + 0x291);
  param_1[0x291] = (long)(param_1 + 0x2c7);
  param_1[0x2c7] = (long)(param_1 + 0x2fd);
  param_1[0x2fd] = (long)(param_1 + 0x333);
  param_1[0x333] = (long)(param_1 + 0x369);
  param_1[0x369] = (long)(param_1 + 0x39f);
  param_1[0x39f] = (long)(param_1 + 0x3d5);
  param_1[0x3d5] = (long)(param_1 + 0x40b);
  param_1[0x40b] = (long)(param_1 + 0x441);
  param_1[0x441] = (long)(param_1 + 0x477);
  param_1[0x477] = (long)(param_1 + 0x4ad);
  param_1[0x4ad] = (long)(param_1 + 0x4e3);
  param_1[0x4e3] = (long)(param_1 + 0x519);
  param_1[0x519] = (long)(param_1 + 0x54f);
  param_1[0x54f] = (long)(param_1 + 0x585);
  param_1[0x585] = (long)(param_1 + 0x5bb);
  param_1[0x5bb] = (long)(param_1 + 0x5f1);
  param_1[0x5f1] = (long)(param_1 + 0x627);
  param_1[0x627] = (long)(param_1 + 0x65d);
  param_1[0x65d] = (long)(param_1 + 0x693);
  param_1[0x693] = (long)(param_1 + 0x6c9);
  param_1[0x6c9] = (long)(param_1 + 0x6ff);
  param_1[0x6ff] = (long)(param_1 + 0x735);
  param_1[0x735] = (long)(param_1 + 0x76b);
  param_1[0x76b] = (long)(param_1 + 0x7a1);
  param_1[0x7a1] = (long)(param_1 + 0x7d7);
  param_1[0x7d7] = (long)(param_1 + 0x80d);
  param_1[0x80d] = (long)(param_1 + 0x843);
  if (param_1 + 0x879 != (long *)0x0) {
    param_1[5] = 0x2800000000;
    param_1[6] = (long)(param_1 + 0x879);
  }
  param_1[0x8a2] = 0;
  *(undefined4 *)(param_1 + 0x8a1) = 0;
  return;
}



void FUN_7101511c0c(long *param_1)

{
  long lVar1;
  
  *(undefined4 *)(param_1 + 2) = 0;
  *(undefined1 *)((long)param_1 + 0x3c) = 0;
  param_1[5] = 0;
  param_1[6] = (long)param_1 + 0x3c;
  *(undefined1 *)((long)param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 7) = 0x40;
  *(undefined1 *)((long)param_1 + 0x7b) = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  lVar1 = DAT_7103a61890 + 0x10;
  *(undefined4 *)(param_1 + 0x13) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x15) = 0;
  *(undefined4 *)(param_1 + 0x16) = 0;
  *(undefined4 *)(param_1 + 0x17) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x19) = 0;
  *(undefined4 *)(param_1 + 0x1a) = 0;
  *(undefined4 *)(param_1 + 0x1b) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 0x1d) = 0;
  *(undefined4 *)(param_1 + 0x1e) = 0;
  *(undefined4 *)(param_1 + 0x1f) = 0;
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined4 *)(param_1 + 0x21) = 0;
  *(undefined4 *)(param_1 + 0x22) = 0;
  *(undefined4 *)(param_1 + 0x23) = 0;
  *(undefined4 *)(param_1 + 0x24) = 0;
  *(undefined4 *)(param_1 + 0x25) = 0;
  *(undefined4 *)(param_1 + 0x26) = 0;
  *(undefined4 *)(param_1 + 0x27) = 0;
  *(undefined4 *)(param_1 + 0x28) = 0;
  *(undefined4 *)(param_1 + 0x29) = 0;
  *(undefined4 *)(param_1 + 0x2a) = 0;
  *(undefined4 *)(param_1 + 0x2b) = 0;
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x2d) = 0;
  *(undefined4 *)(param_1 + 0x2e) = 0;
  *(undefined4 *)(param_1 + 0x2f) = 0;
  *(undefined4 *)(param_1 + 0x30) = 0;
  *(undefined4 *)(param_1 + 0x31) = 0;
  *(undefined4 *)(param_1 + 0x32) = 0;
  *(undefined4 *)(param_1 + 0x33) = 0;
  *(undefined4 *)(param_1 + 0x34) = 0;
  *(undefined4 *)(param_1 + 0x35) = 0;
  *(undefined4 *)(param_1 + 0x36) = 0;
  *(undefined4 *)(param_1 + 0x37) = 0;
  *(undefined4 *)(param_1 + 0x38) = 0;
  *(undefined4 *)(param_1 + 0x39) = 0;
  *(undefined4 *)(param_1 + 0x3a) = 0;
  *(undefined4 *)(param_1 + 0x3b) = 0;
  *(undefined4 *)(param_1 + 0x3c) = 0;
  *(undefined4 *)(param_1 + 0x3d) = 0;
  *(undefined4 *)(param_1 + 0x3e) = 0;
  *(undefined4 *)(param_1 + 0x3f) = 0;
  *(undefined4 *)(param_1 + 0x40) = 0;
  *(undefined4 *)(param_1 + 0x41) = 0;
  *(undefined4 *)(param_1 + 0x42) = 0;
  *(undefined4 *)(param_1 + 0x43) = 0;
  *(undefined4 *)(param_1 + 0x44) = 0;
  *(undefined4 *)(param_1 + 0x45) = 0;
  *(undefined4 *)(param_1 + 0x46) = 0;
  *(undefined4 *)(param_1 + 0x47) = 0;
  *(undefined4 *)(param_1 + 0x48) = 0;
  *(undefined4 *)(param_1 + 0x49) = 0;
  *(undefined4 *)(param_1 + 0x4a) = 0;
  *(undefined4 *)(param_1 + 0x4b) = 0;
  *(undefined4 *)(param_1 + 0x4c) = 0;
  *(undefined4 *)(param_1 + 0x4d) = 0;
  *(undefined4 *)(param_1 + 0x4e) = 0;
  *(undefined4 *)(param_1 + 0x4f) = 0;
  *(undefined4 *)(param_1 + 0x50) = 0;
  *(undefined4 *)(param_1 + 0x51) = 0;
  *(undefined4 *)(param_1 + 0x52) = 0;
  *(undefined4 *)(param_1 + 0x53) = 0;
  *(undefined4 *)(param_1 + 0x54) = 0;
  *(undefined4 *)(param_1 + 0x55) = 0;
  *(undefined4 *)(param_1 + 0x56) = 0;
  *(undefined4 *)(param_1 + 0x57) = 0;
  *(undefined4 *)(param_1 + 0x58) = 0;
  *(undefined4 *)(param_1 + 0x59) = 0;
  *(undefined4 *)(param_1 + 0x5a) = 0;
  *(undefined4 *)(param_1 + 0x5b) = 0;
  *(undefined4 *)(param_1 + 0x5c) = 0;
  *(undefined4 *)(param_1 + 0x5d) = 0;
  *(undefined4 *)(param_1 + 0x5e) = 0;
  *(undefined4 *)(param_1 + 0x5f) = 0;
  *(undefined4 *)(param_1 + 0x60) = 0;
  *(undefined4 *)(param_1 + 0x61) = 0;
  *(undefined4 *)(param_1 + 0x62) = 0;
  *(undefined4 *)(param_1 + 99) = 0;
  *(undefined4 *)(param_1 + 100) = 0;
  *(undefined4 *)(param_1 + 0x65) = 0;
  *(undefined4 *)(param_1 + 0x66) = 0;
  *(undefined4 *)(param_1 + 0x67) = 0;
  *(undefined4 *)(param_1 + 0x68) = 0;
  *(undefined4 *)(param_1 + 0x69) = 0;
  *(undefined4 *)(param_1 + 0x6a) = 0;
  *(undefined4 *)(param_1 + 0x6b) = 0;
  *(undefined4 *)(param_1 + 0x6c) = 0;
  *(undefined4 *)(param_1 + 0x6d) = 0;
  *(undefined4 *)(param_1 + 0x6e) = 0;
  *(undefined4 *)(param_1 + 0x6f) = 0;
  *(undefined4 *)(param_1 + 0x70) = 0;
  *(undefined4 *)(param_1 + 0x71) = 0;
  *(undefined4 *)(param_1 + 0x72) = 0;
  *(undefined4 *)(param_1 + 0x73) = 0;
  *(undefined4 *)(param_1 + 0x74) = 0;
  *(undefined4 *)(param_1 + 0x75) = 0;
  *(undefined4 *)(param_1 + 0x76) = 0;
  *(undefined4 *)(param_1 + 0x77) = 0;
  *(undefined4 *)(param_1 + 0x78) = 0;
  *(undefined4 *)(param_1 + 0x79) = 0;
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *(undefined4 *)(param_1 + 0x7b) = 0;
  *(undefined4 *)(param_1 + 0x7c) = 0;
  *(undefined4 *)(param_1 + 0x7d) = 0;
  *(undefined4 *)(param_1 + 0x7e) = 0;
  *(undefined4 *)(param_1 + 0x7f) = 0;
  *(undefined4 *)(param_1 + 0x80) = 0;
  *(undefined4 *)(param_1 + 0x81) = 0;
  *(undefined4 *)(param_1 + 0x82) = 0;
  *(undefined4 *)(param_1 + 0x83) = 0;
  *(undefined4 *)(param_1 + 0x84) = 0;
  *(undefined4 *)(param_1 + 0x85) = 0;
  *(undefined4 *)(param_1 + 0x86) = 0;
  *(undefined4 *)(param_1 + 0x87) = 0;
  *(undefined4 *)(param_1 + 0x88) = 0;
  *(undefined4 *)(param_1 + 0x89) = 0;
  *(undefined4 *)(param_1 + 0x8a) = 0;
  *(undefined4 *)(param_1 + 0x8b) = 0;
  *(undefined4 *)(param_1 + 0x8c) = 0;
  *(undefined4 *)(param_1 + 0x8d) = 0;
  *(undefined4 *)(param_1 + 0x8e) = 0;
  *(undefined4 *)(param_1 + 0x8f) = 0;
  *(undefined4 *)(param_1 + 0x90) = 0;
  *(undefined4 *)(param_1 + 0x91) = 0;
  *param_1 = lVar1;
  param_1[1] = 0;
  *(undefined4 *)(param_1 + 0x12) = 0;
  param_1[0x10] = (long)(param_1 + 0x12);
  param_1[0x11] = 0x8000000000;
  thunk_EXT_FUN_02e95df0(param_1 + 0x92,0,0x204);
  return;
}



void FUN_7101511e60(long *param_1)

{
  long lVar1;
  long *plVar2;
  
  *(undefined4 *)(param_1 + 2) = 0;
  *(undefined1 *)((long)param_1 + 0x3c) = 0;
  param_1[5] = 0;
  param_1[6] = (long)param_1 + 0x3c;
  *(undefined1 *)((long)param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 7) = 0x40;
  *(undefined1 *)((long)param_1 + 0x7b) = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  lVar1 = DAT_7103a61708 + 0x10;
  param_1[0x18] = 0;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  *param_1 = lVar1;
  param_1[1] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  plVar2 = param_1 + 0x1b;
  do {
    *(undefined4 *)plVar2 = 0;
    *(undefined4 *)(plVar2 + 1) = 0;
    *(undefined4 *)(plVar2 + 2) = 0;
    *(undefined4 *)(plVar2 + 3) = 0;
    *(undefined4 *)(plVar2 + 4) = 0;
    *(undefined4 *)(plVar2 + 5) = 0;
    *(undefined4 *)(plVar2 + 6) = 0;
    *(undefined4 *)(plVar2 + 7) = 0;
    *(undefined4 *)(plVar2 + 8) = 0;
    *(undefined4 *)(plVar2 + 9) = 0;
    plVar2 = plVar2 + 10;
  } while (plVar2 != param_1 + 0x15b);
  param_1[0x19] = (long)(param_1 + 0x1b);
  param_1[0x1a] = 0x14000000000;
  thunk_EXT_FUN_02e95df0(param_1 + 0x15b,0,0x504);
  return;
}



void FUN_7101511f00(undefined8 *param_1)

{
  *(undefined4 *)(param_1 + 2) = 0;
  *(undefined1 *)((long)param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 3) = 0;
  param_1[4] = 0;
  *(undefined4 *)(param_1 + 5) = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  param_1[8] = 0;
  *(undefined4 *)(param_1 + 9) = 0;
  param_1[10] = 0;
  *(undefined4 *)(param_1 + 0xb) = 0;
  param_1[0xc] = 0;
  *(undefined4 *)(param_1 + 0xd) = 0;
  param_1[0xe] = 0;
  *(undefined4 *)(param_1 + 0xf) = 0;
  param_1[0x10] = 0;
  *(undefined4 *)(param_1 + 0x11) = 0;
  param_1[0x12] = 0;
  *param_1 = &DAT_710395ee68;
  param_1[1] = 0;
  return;
}



void FUN_7101511f60(long *param_1)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long *plVar4;
  
  *(undefined4 *)(param_1 + 2) = 0;
  *(undefined1 *)((long)param_1 + 0x3c) = 0;
  param_1[5] = 0;
  param_1[6] = (long)param_1 + 0x3c;
  *(undefined1 *)((long)param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 7) = 0x40;
  *(undefined1 *)((long)param_1 + 0x7b) = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  lVar3 = DAT_7103a61670 + 0x10;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  *param_1 = lVar3;
  param_1[1] = 0;
  param_1[0x14] = (long)(param_1 + 0x16);
  lVar3 = 0;
  while( true ) {
    plVar4 = (long *)((long)param_1 + lVar3 + 0xb8);
    *plVar4 = (long)param_1 + lVar3 + 0xc0;
    *(long **)((long)param_1 + lVar3 + 0xb0) = plVar4;
    *(long *)((long)param_1 + lVar3 + 0xc0) = (long)param_1 + lVar3 + 200;
    if (lVar3 == 0x940) break;
    *(long *)((long)param_1 + lVar3 + 200) = (long)param_1 + lVar3 + 0xd0;
    lVar3 = lVar3 + 0x20;
  }
  param_1[0x141] = 0;
  param_1[0x15] = (long)(param_1 + 0x16);
  if (param_1 + 0x142 != (long *)0x0) {
    param_1[0x12] = 0x12c00000000;
    param_1[0x13] = (long)(param_1 + 0x142);
  }
  param_1[0x26f] = 0;
  plVar4 = param_1 + 0x276;
  param_1[0x26e] = 0;
  lVar3 = 0x128;
  param_1[0x270] = (long)(param_1 + 0x272);
  while( true ) {
    plVar4[-3] = (long)(plVar4 + -2);
    plVar4[-4] = (long)(plVar4 + -3);
    plVar4[-2] = (long)(plVar4 + -1);
    if (lVar3 == 0) break;
    plVar4[-1] = (long)plVar4;
    plVar4 = plVar4 + 4;
    lVar3 = lVar3 + -4;
  }
  param_1[0x39d] = 0;
  param_1[0x271] = (long)(param_1 + 0x272);
  if (param_1 + 0x39e != (long *)0x0) {
    param_1[0x26f] = (long)(param_1 + 0x39e);
    param_1[0x26e] = 0x12c00000000;
  }
  param_1[0x4cb] = 0;
  param_1[0x4ca] = 0;
  param_1[0x4cc] = (long)(param_1 + 0x4ce);
  lVar3 = 0;
  do {
    lVar2 = (long)param_1 + lVar3 + 0x2690;
    *(long *)((long)param_1 + lVar3 + 0x2688) = lVar2;
    lVar1 = lVar3 + 0x38;
    *(long *)((long)param_1 + lVar3 + 0x2670) = lVar2 + -0x18;
    *(long *)((long)param_1 + lVar3 + 0x2678) = lVar2 + -0x10;
    *(long *)((long)param_1 + lVar3 + 0x2680) = lVar2 + -8;
    *(long *)((long)param_1 + lVar3 + 0x2690) = lVar2 + 8;
    *(long *)((long)param_1 + lVar3 + 0x2698) = lVar2 + 0x10;
    *(long *)((long)param_1 + lVar3 + 0x26a0) = lVar2 + 0x18;
    lVar3 = lVar1;
  } while (lVar1 != 0xc78);
  param_1[0x65d] = 0;
  param_1[0x4cd] = (long)(param_1 + 0x4ce);
  if (param_1 + 0x65e != (long *)0x0) {
    param_1[0x4cb] = (long)(param_1 + 0x65e);
    param_1[0x4ca] = 0x19000000000;
  }
  param_1[0x7ef] = 0;
  param_1[0x7ee] = 0;
  plVar4 = param_1 + 0x7f6;
  param_1[0x7f0] = (long)(param_1 + 0x7f2);
  for (lVar3 = 0x94; plVar4[-4] = (long)(plVar4 + -3), lVar3 != 0; lVar3 = lVar3 + -4) {
    plVar4[-1] = (long)plVar4;
    plVar4[-2] = (long)(plVar4 + -1);
    plVar4[-3] = (long)(plVar4 + -2);
    plVar4 = plVar4 + 4;
  }
  param_1[0x887] = 0;
  param_1[0x7f1] = (long)(param_1 + 0x7f2);
  if (param_1 + 0x888 != (long *)0x0) {
    param_1[0x7ef] = (long)(param_1 + 0x888);
    param_1[0x7ee] = 0x9600000000;
  }
  param_1[0x91e] = 0;
  param_1[0x91f] = 0;
  plVar4 = param_1 + 0x926;
  param_1[0x920] = (long)(param_1 + 0x922);
  for (lVar3 = 0x94; plVar4[-4] = (long)(plVar4 + -3), lVar3 != 0; lVar3 = lVar3 + -4) {
    plVar4[-1] = (long)plVar4;
    plVar4[-2] = (long)(plVar4 + -1);
    plVar4[-3] = (long)(plVar4 + -2);
    plVar4 = plVar4 + 4;
  }
  param_1[0x9b7] = 0;
  param_1[0x921] = (long)(param_1 + 0x922);
  if (param_1 + 0x9b8 != (long *)0x0) {
    param_1[0x91f] = (long)(param_1 + 0x9b8);
    param_1[0x91e] = 0x9600000000;
  }
  return;
}



void FUN_71015121c0(long *param_1)

{
  long lVar1;
  long *plVar2;
  
  *(undefined4 *)(param_1 + 2) = 0;
  *(undefined1 *)((long)param_1 + 0x3c) = 0;
  *(undefined1 *)((long)param_1 + 0x14) = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = (long)param_1 + 0x3c;
  lVar1 = DAT_7103a62cc8;
  *(undefined4 *)(param_1 + 7) = 0x40;
  *(undefined1 *)((long)param_1 + 0x7b) = 0;
  *param_1 = lVar1 + 0x10;
  param_1[1] = 0;
  plVar2 = param_1 + 0x12;
  do {
    *(undefined4 *)plVar2 = 0;
    *(undefined4 *)(plVar2 + 1) = 0;
    *(undefined4 *)(plVar2 + 2) = 0;
    *(undefined4 *)(plVar2 + 3) = 0;
    *(undefined4 *)(plVar2 + 4) = 0;
    *(undefined4 *)(plVar2 + 5) = 0;
    *(undefined4 *)(plVar2 + 6) = 0;
    *(undefined4 *)(plVar2 + 7) = 0;
    plVar2 = plVar2 + 8;
  } while (plVar2 != param_1 + 0x812);
  param_1[0x10] = (long)(param_1 + 0x12);
  param_1[0x11] = 0x80000000000;
  thunk_EXT_FUN_02e95df0(param_1 + 0x812,0,0x2004);
  return;
}



void FUN_7101512250(undefined8 *param_1)

{
  undefined8 *puVar1;
  
  *(undefined4 *)(param_1 + 2) = 0;
  *(undefined1 *)((long)param_1 + 0x14) = 0;
  param_1[3] = 0;
  *param_1 = &DAT_7103959508;
  param_1[1] = 0;
  puVar1 = param_1 + 6;
  do {
    *(undefined4 *)puVar1 = 0;
    *(undefined4 *)(puVar1 + 1) = 0;
    *(undefined4 *)(puVar1 + 2) = 0;
    *(undefined4 *)(puVar1 + 3) = 0;
    *(undefined4 *)(puVar1 + 4) = 0;
    *(undefined4 *)(puVar1 + 5) = 0;
    *(undefined4 *)(puVar1 + 6) = 0;
    *(undefined4 *)(puVar1 + 7) = 0;
    *(undefined4 *)(puVar1 + 8) = 0;
    *(undefined4 *)(puVar1 + 9) = 0;
    *(undefined4 *)(puVar1 + 10) = 0;
    *(undefined4 *)(puVar1 + 0xb) = 0;
    *(undefined4 *)(puVar1 + 0xc) = 0;
    *(undefined4 *)(puVar1 + 0xd) = 0;
    puVar1 = puVar1 + 0xe;
  } while (puVar1 != param_1 + 0xe06);
  param_1[4] = param_1 + 6;
  param_1[5] = 0xe0000000000;
  thunk_EXT_FUN_02e95df0(param_1 + 0xe06,0,0x3804);
  param_1[0x1507] = &DAT_710395bdf8;
  param_1[0x15ea] = &DAT_710395bdf8;
  param_1[0x1508] = param_1 + 0x150a;
  param_1[0x1509] = 0x1c0;
  param_1[0x15eb] = param_1 + 0x15ed;
  param_1[0x15ec] = 0x1c0;
  param_1[0x16ce] = param_1 + 0x16d0;
  param_1[0x16cf] = 0x10;
  param_1[0x16d9] = param_1 + 0x16db;
  param_1[0x16da] = 0x10;
  param_1[0x16cd] = &DAT_710395be18;
  param_1[0x16d8] = &DAT_710395be18;
  thunk_EXT_FUN_02e95df0(param_1 + 0x16e3,0,0x1420);
  param_1[0x1967] = &DAT_710395be38;
  param_1[0x1968] = param_1 + 0x196a;
  param_1[0x1969] = 0x280;
  param_1[0x1beb] = param_1 + 0x1bed;
  param_1[0x1bec] = 0x100;
  param_1[0x1bea] = &DAT_710395be58;
  return;
}



void FUN_71015123d0(long param_1)

{
  undefined8 *puVar1;
  long *plVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 in_x6;
  undefined8 in_x7;
  long *plVar6;
  uint uVar7;
  undefined1 *puVar8;
  uint uVar9;
  undefined1 *local_f8;
  undefined1 *local_f0;
  int local_e8;
  undefined1 local_e4 [127];
  undefined1 local_65;
  
  uVar7 = 0;
  do {
    puVar1 = (undefined8 *)(param_1 + 0x10) + uVar7;
    if (0x8b < uVar7) {
      puVar1 = (undefined8 *)(param_1 + 0x10);
    }
    plVar6 = (long *)*puVar1;
    if (plVar6 != (long *)0x0) {
      if (uVar7 < 0x8c) {
        uVar3 = 8;
        uVar4 = 1;
        uVar5 = 0;
        puVar8 = *(undefined1 **)(DAT_7103a619b0 + (ulong)uVar7 * 8 + 0x9d8);
        local_f0 = puVar8;
        plVar2 = FUN_71024eaadc(0,(long *)&local_f0,*(long **)(param_1 + 8),8,1,0);
      }
      else {
        local_f0 = &DAT_71030e70e0;
        uVar3 = 8;
        uVar4 = 1;
        uVar5 = 0;
        plVar2 = FUN_71024eaadc(0,(long *)&local_f0,*(long **)(param_1 + 8),8,1,0);
        puVar8 = &DAT_71030e70e0;
      }
      local_e8 = 0x80;
      local_65 = 0;
      local_e4[0] = 0;
      local_f8 = puVar8;
      local_f0 = local_e4;
      FUN_7100bbdd20((long *)&local_f0,0x71030de94a,(long *)&local_f8,uVar3,uVar4,uVar5,in_x6,in_x7)
      ;
      local_f0[(long)local_e8 + -1] = 0;
      plVar6[1] = (long)plVar2;
      *(uint *)(plVar6 + 2) = uVar7;
      (**(code **)(*plVar6 + 0x30))(plVar6,plVar2);
      *(undefined1 *)((long)plVar6 + 0x14) = 1;
      (**(code **)(*plVar2 + 0x28))(plVar2);
    }
    uVar9 = 0x8c;
    if ((int)uVar7 < 0x8c) {
      uVar9 = uVar7 + 1;
    }
    uVar7 = uVar9;
  } while (uVar9 != 0x8c);
  return;
}



void FUN_7101512540(long param_1)

{
  int iVar1;
  undefined8 *puVar2;
  
  puVar2 = *(undefined8 **)(param_1 + 0x28);
  if (puVar2 != (undefined8 *)0x0) {
    if ((*DAT_7103a61988 & 1) == 0) {
      iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61988);
      if (iVar1 != 0) {
        *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a61988);
      }
    }
                    // WARNING: Could not recover jumptable at 0x00710151257c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)*puVar2)(puVar2,DAT_7103a61980);
    return;
  }
  return;
}



void FUN_71015125d0(long param_1)

{
  int iVar1;
  undefined8 *puVar2;
  
  puVar2 = *(undefined8 **)(param_1 + 0xa8);
  if (puVar2 != (undefined8 *)0x0) {
    if ((DAT_71040790e0 & 1) == 0) {
      iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040790e0);
      if (iVar1 != 0) {
        DAT_71040790d8 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(&DAT_71040790e0);
      }
    }
                    // WARNING: Could not recover jumptable at 0x00710151260c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)*puVar2)(puVar2,&DAT_71040790d8);
    return;
  }
  return;
}



long * FUN_71015127ec(void)

{
  int iVar1;
  
  if (((*DAT_7103a608c0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a608c0), iVar1 != 0))
  {
    *DAT_7103a608b8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a608c0);
  }
  return DAT_7103a608b8;
}



void FUN_7101512850(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101512890. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71015128b0(long *param_1,long *param_2)

{
  uint *puVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  char cVar8;
  undefined2 uVar9;
  undefined8 uVar10;
  bool bVar11;
  int iVar12;
  uint uVar13;
  long lVar14;
  ulong uVar15;
  long lVar16;
  undefined4 *puVar17;
  byte *pbVar18;
  uint uVar19;
  undefined4 *puVar20;
  undefined8 *puVar21;
  undefined8 *puVar22;
  long lVar23;
  byte *pbVar24;
  long *plVar25;
  byte *local_200;
  undefined8 local_1f8;
  undefined8 local_1f0;
  undefined2 local_1e8;
  undefined1 local_175;
  byte *local_170;
  uint *puStack_168;
  undefined8 local_160;
  undefined2 local_158;
  long local_150;
  undefined8 local_148;
  undefined1 *local_140;
  undefined8 ***pppuStack_138;
  undefined8 ***local_130;
  undefined8 ***local_128 [4];
  undefined8 **local_108 [4];
  undefined8 *local_e8 [4];
  undefined8 local_c8 [4];
  undefined1 local_a8 [32];
  undefined8 local_88;
  undefined4 local_80;
  undefined4 local_78;
  undefined4 local_70;
  undefined1 local_6c;
  
  plVar25 = *(long **)(*DAT_7103a5a038 + 0xa8);
  if (((DAT_7104078e60 & 1) == 0) && (iVar12 = thunk_EXT_FUN_02e95df0(&DAT_7104078e60), iVar12 != 0)
     ) {
    DAT_7104078e58 = 0xc0;
    thunk_EXT_FUN_02e95df0(&DAT_7104078e60);
  }
  pbVar18 = DAT_7103a619e8;
  if (DAT_7104078e58 != 0xc0) {
    uVar19 = DAT_7104078e58;
    if (*(uint *)(*plVar25 + 0x10) <= DAT_7104078e58) {
      uVar19 = 0;
    }
    puVar21 = *(undefined8 **)(*(long *)(*plVar25 + 0x18) + (long)(int)uVar19 * 0x28 + 0x20);
    if (((*DAT_7103a619e8 & 1) == 0) &&
       (iVar12 = thunk_EXT_FUN_02e95df0(DAT_7103a619e8), iVar12 != 0)) {
      *DAT_7103a619e0 = &DAT_710395adf0;
      thunk_EXT_FUN_02e95df0(DAT_7103a619e8);
    }
    if ((puVar21 != (undefined8 *)0x0) &&
       (lVar14 = (**(code **)*puVar21)(puVar21,DAT_7103a619e0), uVar19 = DAT_7104078e58, lVar14 != 0
       )) {
LAB_71015129f8:
      DAT_7104078e58 = uVar19;
      param_1[3] = (long)param_2;
      local_108[0] = local_e8;
      pppuStack_138 = local_128;
      local_e8[0] = local_c8;
      local_c8[0] = 0;
      local_128[0] = local_108;
      local_148 = 0;
      local_140 = (undefined1 *)0x0;
      if (local_a8 != (undefined1 *)0x0) {
        local_148 = 0x400000000;
        local_140 = local_a8;
      }
      local_6c = 0;
      local_88 = 0xffffffff;
      local_80 = 2;
      local_78 = 0xffffffff;
      local_70 = 0xffffffff;
      local_150 = lVar14;
      local_130 = pppuStack_138;
      uVar15 = FUN_710290dde0(&local_150);
      iVar12 = (int)uVar15;
      if (0 < (int)local_148) {
        lVar23 = 0;
        do {
          (**(code **)(**(long **)(local_140 + lVar23 * 8) + 0x18))();
          lVar23 = lVar23 + 1;
        } while (lVar23 < (int)local_148);
      }
      pbVar24 = (byte *)param_1[6];
      pbVar18 = *(byte **)(lVar14 + 0x18);
      if (pbVar24 != pbVar18) {
        if (pbVar18 == (byte *)0x0) {
LAB_7101512ae4:
          uVar15 = 0;
        }
        else {
          uVar15 = (ulong)*pbVar18;
          if (*pbVar18 != 0) {
            uVar15 = 0;
            do {
              if (uVar15 == 0x400000) goto LAB_7101512ae4;
              if (pbVar18[uVar15 + 1] == 0) {
                uVar15 = uVar15 + 1;
                break;
              }
              lVar23 = uVar15 + 2;
              uVar15 = uVar15 + 2;
            } while (pbVar18[lVar23] != 0);
          }
        }
        iVar3 = (int)uVar15;
        if ((int)param_1[7] <= (int)uVar15) {
          iVar3 = (int)param_1[7] + -1;
        }
        thunk_EXT_FUN_02e95df0(pbVar24,pbVar18,(long)iVar3);
        pbVar24[iVar3] = 0;
      }
      if (iVar12 == 0) goto LAB_7101512df4;
      *(undefined1 *)((long)(int)param_1[7] + param_1[6] + -1) = 0;
      if (0 < iVar12) {
        uVar15 = (ulong)(uint)(iVar12 << 1);
        lVar23 = *DAT_7103a65db8;
        if (lVar23 == 0) {
          puVar17 = (undefined4 *)FUN_71005fbcb0(8,uVar15 << 4);
        }
        else {
          plVar25 = param_2;
          if (param_2 == (long *)0x0) {
            lVar16 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(*DAT_7103a66138 + 0x68));
            plVar25 = (long *)(lVar23 + 8);
            if (lVar16 != 0) {
              plVar25 = (long *)(lVar16 + 0x88);
            }
            plVar25 = (long *)*plVar25;
            if (plVar25 == (long *)0x0) goto LAB_7101512bcc;
          }
          puVar17 = (undefined4 *)(**(code **)(*plVar25 + 0x30))(plVar25,uVar15 << 4,8);
        }
        puVar20 = puVar17;
        if (puVar17 != (undefined4 *)0x0) {
          do {
            *puVar20 = 0;
            uVar15 = uVar15 - 2;
            puVar20[4] = 0;
            puVar20 = puVar20 + 8;
          } while (uVar15 != 0);
          param_1[4] = (long)puVar17;
          *(undefined4 *)(param_1 + 5) = 0;
          *(int *)((long)param_1 + 0x2c) = iVar12 << 1;
        }
      }
LAB_7101512bcc:
      local_148 = 0;
      pppuStack_138 = local_128;
      local_128[0] = local_108;
      local_108[0] = local_e8;
      local_e8[0] = local_c8;
      local_140 = (undefined1 *)0x0;
      local_c8[0] = 0;
      if (local_a8 != (undefined1 *)0x0) {
        local_148 = 0x400000000;
        local_140 = local_a8;
      }
      local_88 = 0xffffffff;
      local_80 = 2;
      local_78 = 0xffffffff;
      local_70 = 0xffffffff;
      local_6c = 0;
      local_1f0 = 0xffffffff00000000;
      local_1e8 = 0;
      local_200 = (byte *)0x0;
      local_1f8 = (uint *)0x0;
      local_150 = lVar14;
      local_130 = pppuStack_138;
      FUN_710290da90(&local_200,&local_150,0);
      puVar7 = local_1f8;
      pbVar18 = local_200;
      local_158 = local_1e8;
      uVar9 = local_158;
      local_170 = local_200;
      puStack_168 = local_1f8;
      local_160 = local_1f0;
      uVar10 = local_160;
      local_158._1_1_ = (char)((ushort)local_1e8 >> 8);
      bVar11 = local_158._1_1_ == '\0';
      local_158 = uVar9;
      if (bVar11) {
        local_158._0_1_ = (char)local_1e8;
        cVar8 = (char)local_158;
        bVar11 = (char)local_158 == '\0';
        local_160._0_4_ = (uint)local_1f0;
        local_160._4_4_ = (int)((ulong)local_1f0 >> 0x20);
        iVar3 = local_160._4_4_;
        uVar19 = (uint)local_160;
        iVar12 = -1;
        if (bVar11) {
          iVar12 = 1;
        }
        do {
          local_160 = uVar10;
          if (puVar7 == (uint *)0x0) {
            puVar21 = (undefined8 *)
                      (**(code **)(**(long **)pbVar18 + 0x80))(*(long **)pbVar18,uVar19);
          }
          else {
            uVar13 = uVar19;
            if (*puVar7 <= uVar19) {
              uVar13 = 0;
            }
            puVar21 = *(undefined8 **)(*(long *)(puVar7 + 2) + (long)(int)uVar13 * 8);
          }
          local_175 = 0;
          local_1f8 = (uint *)CONCAT35(local_1f8._5_3_,0x80);
          local_200 = (byte *)((long)&local_1f8 + 4);
          FUN_710290e160(puVar21,&local_200);
          local_200[(long)(int)local_1f8 + -1] = 0;
          uVar13 = FUN_7100bb2120(local_200,0);
          lVar14 = (**(code **)(*param_1 + 0x50))(param_1,param_2,uVar13,puVar21);
          if ((uVar13 != 0) && (lVar14 != 0)) {
            uVar2 = *(uint *)((long)param_1 + 0x2c);
            uVar5 = 0;
            if (uVar2 != 0) {
              uVar5 = uVar13 / uVar2;
            }
            uVar5 = uVar13 - uVar5 * uVar2;
            uVar6 = uVar5;
            do {
              uVar4 = *(uint *)(param_1[4] +
                               (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
              if (uVar4 == 0) {
                puVar1 = (uint *)(param_1[4] + (long)(int)uVar6 * 0x10);
                *puVar1 = uVar13;
                *(long *)(puVar1 + 2) = lVar14;
                *(int *)(param_1 + 5) = (int)param_1[5] + 1;
                break;
              }
              if (uVar4 == uVar13) break;
              uVar4 = 0;
              if ((int)(uVar6 + 1) < (int)uVar2) {
                uVar4 = uVar6 + 1;
              }
              uVar6 = uVar4;
            } while (uVar4 != uVar5);
          }
          do {
            uVar19 = uVar19 + iVar12;
            local_160 = CONCAT44(local_160._4_4_,uVar19);
            if (cVar8 == '\0') {
              if (iVar3 < (int)uVar19) goto LAB_7101512db8;
            }
            else if ((int)uVar19 < iVar3) goto LAB_7101512db8;
            uVar13 = FUN_710290dcb0(&local_170);
            uVar10 = local_160;
          } while ((uVar13 & 1) == 0);
        } while( true );
      }
LAB_7101512db8:
      if (0 < (int)local_148) {
        lVar14 = 0;
        do {
          (**(code **)(**(long **)(local_140 + lVar14 * 8) + 0x18))();
          lVar14 = lVar14 + 1;
        } while (lVar14 < (int)local_148);
      }
      goto LAB_7101512df4;
    }
  }
  puVar21 = DAT_7103a619e0;
  lVar14 = *plVar25;
  uVar13 = *(uint *)(lVar14 + 0x10);
  if (0 < (int)uVar13) {
    uVar19 = 0;
    do {
      uVar2 = uVar19;
      if (uVar13 <= uVar19) {
        uVar2 = 0;
      }
      puVar22 = *(undefined8 **)(*(long *)(lVar14 + 0x18) + (ulong)uVar2 * 0x28 + 0x20);
      if (((*pbVar18 & 1) == 0) && (iVar12 = thunk_EXT_FUN_02e95df0(pbVar18), iVar12 != 0)) {
        *puVar21 = &DAT_710395adf0;
        thunk_EXT_FUN_02e95df0(pbVar18);
      }
      if ((puVar22 != (undefined8 *)0x0) &&
         (lVar14 = (**(code **)*puVar22)(puVar22,puVar21), lVar14 != 0)) goto LAB_71015129f8;
      lVar14 = *plVar25;
      uVar19 = uVar19 + 1;
      uVar13 = *(uint *)(lVar14 + 0x10);
    } while ((int)uVar19 < (int)uVar13);
  }
LAB_7101512df4:
                    // WARNING: Could not recover jumptable at 0x007101512e20. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x40))(param_1,param_2);
  return;
}



void FUN_71015130ac(undefined8 *param_1)

{
  long *plVar1;
  undefined8 *local_8;
  
  *param_1 = &DAT_710395e318;
  local_8 = param_1;
  if ((long *)param_1[1] != (long *)0x0) {
    FUN_7101513120((long *)param_1[1],&local_8);
  }
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
  }
  else {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    }
  }
  return;
}



void FUN_7101513120(long *param_1,undefined8 param_2)

{
  long *plVar1;
  
  do {
    if ((long *)*param_1 != (long *)0x0) {
      FUN_7101513120((long *)*param_1,param_2);
    }
    plVar1 = (long *)param_1[1];
    param_1[5] = 0;
    *param_1 = 0;
    param_1[1] = 0;
    param_1 = plVar1;
  } while (plVar1 != (long *)0x0);
  return;
}



undefined8 FUN_7101513174(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a61a20 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61a20), iVar1 != 0))
  {
    *DAT_7103a61a18 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61a20);
  }
  if (param_2 != DAT_7103a61a18) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101513274(void)

{
  int iVar1;
  
  if (((*DAT_7103a61a20 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61a20), iVar1 != 0))
  {
    *DAT_7103a61a18 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61a20);
  }
  return DAT_7103a61a18;
}



void FUN_71015132d8(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101513318. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101513bf8(void)

{
  int iVar1;
  
  if (((*DAT_7103a61a58 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61a58), iVar1 != 0))
  {
    *DAT_7103a61a50 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61a58);
  }
  return DAT_7103a61a50;
}



void FUN_7101513c5c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101513c9c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101514578(void)

{
  int iVar1;
  
  if (((*DAT_7103a61a90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61a90), iVar1 != 0))
  {
    *DAT_7103a61a88 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61a90);
  }
  return DAT_7103a61a88;
}



void FUN_71015145dc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151461c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101514e3c(undefined8 *param_1)

{
  long *plVar1;
  undefined8 *local_8;
  
  *param_1 = &DAT_710395e370;
  local_8 = param_1;
  if ((long *)param_1[1] != (long *)0x0) {
    FUN_7101514eb0((long *)param_1[1],&local_8);
  }
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
  }
  else {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    }
  }
  return;
}



void FUN_7101514eb0(long *param_1,undefined8 param_2)

{
  long *plVar1;
  
  do {
    if ((long *)*param_1 != (long *)0x0) {
      FUN_7101514eb0((long *)*param_1,param_2);
    }
    plVar1 = (long *)param_1[1];
    param_1[5] = 0;
    *param_1 = 0;
    param_1[1] = 0;
    param_1 = plVar1;
  } while (plVar1 != (long *)0x0);
  return;
}



undefined8 FUN_7101514f04(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a5ea58 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5ea58), iVar1 != 0))
  {
    *DAT_7103a5ea50 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5ea58);
  }
  if (param_2 != DAT_7103a5ea50) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101515004(void)

{
  int iVar1;
  
  if (((*DAT_7103a5ea58 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5ea58), iVar1 != 0))
  {
    *DAT_7103a5ea50 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5ea58);
  }
  return DAT_7103a5ea50;
}



void FUN_7101515068(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015150a8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101515888(undefined8 *param_1)

{
  undefined8 *puVar1;
  
  param_1[0x67] = 0;
  param_1[0x1f] = param_1 + 0x20;
  param_1[0x1e] = param_1 + 0x1f;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[0x1d] = param_1 + 0x1e;
  param_1[0x1c] = param_1 + 0x1d;
  param_1[0x1b] = param_1 + 0x1c;
  param_1[0x1a] = param_1 + 0x1b;
  param_1[0x19] = param_1 + 0x1a;
  param_1[0x18] = param_1 + 0x19;
  param_1[0x17] = param_1 + 0x18;
  param_1[0x16] = param_1 + 0x17;
  param_1[0x15] = param_1 + 0x16;
  param_1[0x14] = param_1 + 0x15;
  param_1[0x13] = param_1 + 0x14;
  param_1[0x12] = param_1 + 0x13;
  param_1[0x11] = param_1 + 0x12;
  param_1[0x10] = param_1 + 0x11;
  param_1[0xf] = param_1 + 0x10;
  param_1[0xe] = param_1 + 0xf;
  param_1[0xd] = param_1 + 0xe;
  param_1[0xc] = param_1 + 0xd;
  param_1[0xb] = param_1 + 0xc;
  param_1[10] = param_1 + 0xb;
  param_1[9] = param_1 + 10;
  param_1[8] = param_1 + 9;
  param_1[7] = param_1 + 8;
  param_1[6] = param_1 + 7;
  param_1[5] = param_1 + 6;
  puVar1 = param_1 + 4;
  *puVar1 = param_1 + 5;
  param_1[0x20] = param_1 + 0x21;
  param_1[0x21] = param_1 + 0x22;
  param_1[0x22] = param_1 + 0x23;
  param_1[0x23] = param_1 + 0x24;
  param_1[0x24] = param_1 + 0x25;
  param_1[0x25] = param_1 + 0x26;
  param_1[0x26] = param_1 + 0x27;
  param_1[0x27] = param_1 + 0x28;
  param_1[0x28] = param_1 + 0x29;
  param_1[0x29] = param_1 + 0x2a;
  param_1[0x2a] = param_1 + 0x2b;
  param_1[0x2b] = param_1 + 0x2c;
  param_1[0x2c] = param_1 + 0x2d;
  param_1[0x2d] = param_1 + 0x2e;
  param_1[0x2e] = param_1 + 0x2f;
  param_1[0x2f] = param_1 + 0x30;
  param_1[0x30] = param_1 + 0x31;
  param_1[0x31] = param_1 + 0x32;
  param_1[0x32] = param_1 + 0x33;
  param_1[0x33] = param_1 + 0x34;
  param_1[0x34] = param_1 + 0x35;
  param_1[0x35] = param_1 + 0x36;
  param_1[0x36] = param_1 + 0x37;
  param_1[0x37] = param_1 + 0x38;
  param_1[0x38] = param_1 + 0x39;
  param_1[0x39] = param_1 + 0x3a;
  param_1[0x3a] = param_1 + 0x3b;
  param_1[0x3b] = param_1 + 0x3c;
  param_1[0x3c] = param_1 + 0x3d;
  param_1[0x3d] = param_1 + 0x3e;
  param_1[0x3e] = param_1 + 0x3f;
  param_1[0x3f] = param_1 + 0x40;
  param_1[0x40] = param_1 + 0x41;
  param_1[0x41] = param_1 + 0x42;
  param_1[0x42] = param_1 + 0x43;
  param_1[0x43] = param_1 + 0x44;
  param_1[0x44] = param_1 + 0x45;
  param_1[0x45] = param_1 + 0x46;
  param_1[0x46] = param_1 + 0x47;
  param_1[0x47] = param_1 + 0x48;
  param_1[0x48] = param_1 + 0x49;
  param_1[0x49] = param_1 + 0x4a;
  param_1[0x4a] = param_1 + 0x4b;
  param_1[0x4b] = param_1 + 0x4c;
  param_1[0x4c] = param_1 + 0x4d;
  param_1[0x4d] = param_1 + 0x4e;
  param_1[0x4e] = param_1 + 0x4f;
  param_1[0x4f] = param_1 + 0x50;
  param_1[0x50] = param_1 + 0x51;
  param_1[0x51] = param_1 + 0x52;
  param_1[0x52] = param_1 + 0x53;
  param_1[0x53] = param_1 + 0x54;
  param_1[0x54] = param_1 + 0x55;
  param_1[0x55] = param_1 + 0x56;
  param_1[0x56] = param_1 + 0x57;
  param_1[0x57] = param_1 + 0x58;
  param_1[0x58] = param_1 + 0x59;
  param_1[0x59] = param_1 + 0x5a;
  param_1[0x5a] = param_1 + 0x5b;
  param_1[0x5b] = param_1 + 0x5c;
  param_1[0x5c] = param_1 + 0x5d;
  param_1[0x5d] = param_1 + 0x5e;
  param_1[0x5e] = param_1 + 0x5f;
  param_1[0x5f] = param_1 + 0x60;
  param_1[0x60] = param_1 + 0x61;
  param_1[0x61] = param_1 + 0x62;
  param_1[0x62] = param_1 + 99;
  param_1[99] = param_1 + 100;
  param_1[100] = param_1 + 0x65;
  param_1[0x65] = param_1 + 0x66;
  param_1[0x66] = param_1 + 0x67;
  param_1[2] = puVar1;
  param_1[3] = 0;
  param_1[3] = puVar1;
  if (param_1 + 0x68 != (undefined8 *)0x0) {
    *param_1 = 0x6400000000;
    param_1[1] = param_1 + 0x68;
  }
  return;
}



undefined8 FUN_7101515b88(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((DAT_7104078f80 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_7104078f80), iVar1 != 0))
  {
    DAT_7104078f78 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_7104078f80);
  }
  if (param_2 != &DAT_7104078f78) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



undefined8 * FUN_7101515c7c(void)

{
  int iVar1;
  
  if (((DAT_7104078f80 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_7104078f80), iVar1 != 0))
  {
    DAT_7104078f78 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_7104078f80);
  }
  return &DAT_7104078f78;
}



void FUN_7101515cdc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101515d1c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_71015165f8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c638 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c638), iVar1 != 0))
  {
    *DAT_7103a5c630 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c638);
  }
  return DAT_7103a5c630;
}



void FUN_710151665c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151669c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101516f78(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a5f0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a5f0), iVar1 != 0))
  {
    *DAT_7103a5a5e8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a5f0);
  }
  return DAT_7103a5a5e8;
}



void FUN_7101516fdc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151701c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_71015178f8(void)

{
  int iVar1;
  
  if (((*DAT_7103a61748 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61748), iVar1 != 0))
  {
    *DAT_7103a61740 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61748);
  }
  return DAT_7103a61740;
}



void FUN_710151795c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151799c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101518278(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c658 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c658), iVar1 != 0))
  {
    *DAT_7103a5c650 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c658);
  }
  return DAT_7103a5c650;
}



void FUN_71015182dc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151831c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101518bf8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5e9e8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5e9e8), iVar1 != 0))
  {
    *DAT_7103a5e9e0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5e9e8);
  }
  return DAT_7103a5e9e0;
}



void FUN_7101518c5c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101518c9c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long FUN_71015193d4(undefined8 param_1,long *param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long lVar4;
  
  lVar4 = *DAT_7103a65db8;
  if (lVar4 == 0) {
    lVar4 = FUN_71005fbcb0(8,0x18);
  }
  else {
    plVar3 = param_2;
    if (param_2 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar4 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
    }
    lVar4 = (**(code **)(*plVar3 + 0x30))(plVar3,0x18,8);
  }
  FUN_71014ff850(lVar4,param_2,param_4);
  return lVar4;
}



long * FUN_7101519624(void)

{
  int iVar1;
  
  if (((*DAT_7103a59f78 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59f78), iVar1 != 0))
  {
    *DAT_7103a59f70 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a59f78);
  }
  return DAT_7103a59f70;
}



void FUN_7101519688(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015196c8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 * FUN_7101519f9c(void)

{
  int iVar1;
  
  if (((DAT_71040790e0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040790e0), iVar1 != 0))
  {
    DAT_71040790d8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_71040790e0);
  }
  return &DAT_71040790d8;
}



void FUN_7101519ffc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151a03c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151a918(void)

{
  int iVar1;
  
  if (((*DAT_7103a61c68 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61c68), iVar1 != 0))
  {
    *DAT_7103a61c60 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61c68);
  }
  return DAT_7103a61c60;
}



void FUN_710151a97c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151a9bc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151b298(void)

{
  int iVar1;
  
  if (((*DAT_7103a61ca0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61ca0), iVar1 != 0))
  {
    *DAT_7103a61c98 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61ca0);
  }
  return DAT_7103a61c98;
}



void FUN_710151b2fc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151b33c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151bc18(void)

{
  int iVar1;
  
  if (((*DAT_7103a61ce0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61ce0), iVar1 != 0))
  {
    *DAT_7103a61cd8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61ce0);
  }
  return DAT_7103a61cd8;
}



void FUN_710151bc7c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151bcbc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151c598(void)

{
  int iVar1;
  
  if (((*DAT_7103a5e658 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5e658), iVar1 != 0))
  {
    *DAT_7103a5e650 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5e658);
  }
  return DAT_7103a5e650;
}



void FUN_710151c5fc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151c63c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151cf18(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a808 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a808), iVar1 != 0))
  {
    *DAT_7103a5a800 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a808);
  }
  return DAT_7103a5a800;
}



void FUN_710151cf7c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151cfbc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151d898(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a5e0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a5e0), iVar1 != 0))
  {
    *DAT_7103a5a5d8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a5e0);
  }
  return DAT_7103a5a5d8;
}



void FUN_710151d8fc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151d93c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151e218(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a818 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a818), iVar1 != 0))
  {
    *DAT_7103a5a810 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a818);
  }
  return DAT_7103a5a810;
}



void FUN_710151e27c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151e2bc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151eb98(void)

{
  int iVar1;
  
  if (((*DAT_7103a5d9b8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5d9b8), iVar1 != 0))
  {
    *DAT_7103a5d9b0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5d9b8);
  }
  return DAT_7103a5d9b0;
}



void FUN_710151ebfc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151ec3c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151f518(void)

{
  int iVar1;
  
  if (((*DAT_7103a601c0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a601c0), iVar1 != 0))
  {
    *DAT_7103a601b8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a601c0);
  }
  return DAT_7103a601b8;
}



void FUN_710151f57c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151f5bc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710151fe98(void)

{
  int iVar1;
  
  if (((*DAT_7103a5d7f8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5d7f8), iVar1 != 0))
  {
    *DAT_7103a5d7f0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5d7f8);
  }
  return DAT_7103a5d7f0;
}



void FUN_710151fefc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710151ff3c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101520818(void)

{
  int iVar1;
  
  if (((*DAT_7103a60858 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60858), iVar1 != 0))
  {
    *DAT_7103a60850 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60858);
  }
  return DAT_7103a60850;
}



void FUN_710152087c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015208bc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101521198(void)

{
  int iVar1;
  
  if (((*DAT_7103a59fc0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59fc0), iVar1 != 0))
  {
    *DAT_7103a59fb8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a59fc0);
  }
  return DAT_7103a59fb8;
}



void FUN_71015211fc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152123c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101521b18(void)

{
  int iVar1;
  
  if (((*DAT_7103a5fda8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5fda8), iVar1 != 0))
  {
    *DAT_7103a5fda0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fda8);
  }
  return DAT_7103a5fda0;
}



void FUN_7101521b7c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101521bbc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101522498(void)

{
  int iVar1;
  
  if (((*DAT_7103a5fd60 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5fd60), iVar1 != 0))
  {
    *DAT_7103a5fd58 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fd60);
  }
  return DAT_7103a5fd58;
}



void FUN_71015224fc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152253c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101522e18(void)

{
  int iVar1;
  
  if (((*DAT_7103a60da0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60da0), iVar1 != 0))
  {
    *DAT_7103a60d98 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60da0);
  }
  return DAT_7103a60d98;
}



void FUN_7101522e7c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101522ebc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101523798(void)

{
  int iVar1;
  
  if (((*DAT_7103a59f58 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59f58), iVar1 != 0))
  {
    *DAT_7103a59f50 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a59f58);
  }
  return DAT_7103a59f50;
}



void FUN_71015237fc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152383c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101524118(void)

{
  int iVar1;
  
  if (((*DAT_7103a59f38 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59f38), iVar1 != 0))
  {
    *DAT_7103a59f30 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a59f38);
  }
  return DAT_7103a59f30;
}



void FUN_710152417c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015241bc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101524a98(void)

{
  int iVar1;
  
  if (((*DAT_7103a59f18 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59f18), iVar1 != 0))
  {
    *DAT_7103a59f10 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a59f18);
  }
  return DAT_7103a59f10;
}



void FUN_7101524afc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101524b3c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101525338(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101525378. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71015253b8(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015253f8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101525438(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101525478. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71015254b8(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015254f8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 FUN_7101525518(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a5a7b8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a7b8), iVar1 != 0))
  {
    *DAT_7103a5a7b0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a7b8);
  }
  if (param_2 != DAT_7103a5a7b0) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101525618(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a7b8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a7b8), iVar1 != 0))
  {
    *DAT_7103a5a7b0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a7b8);
  }
  return DAT_7103a5a7b0;
}



void FUN_710152567c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015256bc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101525f98(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a4e8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a4e8), iVar1 != 0))
  {
    *DAT_7103a5a4e0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a4e8);
  }
  return DAT_7103a5a4e0;
}



void FUN_7101525ffc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152603c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101526918(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a740 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a740), iVar1 != 0))
  {
    *DAT_7103a5a738 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a740);
  }
  return DAT_7103a5a738;
}



void FUN_710152697c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015269bc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101527298(void)

{
  int iVar1;
  
  if (((*DAT_7103a5ce40 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5ce40), iVar1 != 0))
  {
    *DAT_7103a5ce38 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5ce40);
  }
  return DAT_7103a5ce38;
}



void FUN_71015272fc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152733c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101527b5c(undefined8 *param_1)

{
  long *plVar1;
  undefined8 *local_8;
  
  *param_1 = &DAT_710395e2d8;
  local_8 = param_1;
  if ((long *)param_1[1] != (long *)0x0) {
    FUN_7101527bd0((long *)param_1[1],&local_8);
  }
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
  }
  else {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    }
  }
  return;
}



void FUN_7101527bd0(long *param_1,undefined8 param_2)

{
  long *plVar1;
  
  do {
    if ((long *)*param_1 != (long *)0x0) {
      FUN_7101527bd0((long *)*param_1,param_2);
    }
    plVar1 = (long *)param_1[1];
    param_1[5] = 0;
    *param_1 = 0;
    param_1[1] = 0;
    param_1 = plVar1;
  } while (plVar1 != (long *)0x0);
  return;
}



void FUN_7101527c24(undefined8 *param_1)

{
  undefined8 *local_8;
  
  *param_1 = &DAT_710395e2f8;
  if ((long *)param_1[1] != (long *)0x0) {
    local_8 = param_1;
    FUN_7101527ce0((long *)param_1[1],&local_8);
  }
  *(undefined4 *)(param_1 + 2) = 0;
  param_1[1] = 0;
  return;
}



void FUN_7101527c68(undefined8 *param_1)

{
  long *plVar1;
  undefined8 *local_8;
  
  *param_1 = &DAT_710395e2f8;
  local_8 = param_1;
  if ((long *)param_1[1] != (long *)0x0) {
    FUN_7101527ce0((long *)param_1[1],&local_8);
  }
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
  }
  else {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    }
  }
  return;
}



void FUN_7101527ce0(long *param_1,undefined8 param_2)

{
  long *plVar1;
  
  do {
    if ((long *)*param_1 != (long *)0x0) {
      FUN_7101527ce0((long *)*param_1,param_2);
    }
    plVar1 = (long *)param_1[1];
    param_1[5] = 0;
    *param_1 = 0;
    param_1[1] = 0;
    param_1 = plVar1;
  } while (plVar1 != (long *)0x0);
  return;
}



void FUN_7101527d34(undefined8 *param_1)

{
  undefined8 *local_8;
  
  *param_1 = &DAT_710395e338;
  if ((long *)param_1[1] != (long *)0x0) {
    local_8 = param_1;
    FUN_7101527df0((long *)param_1[1],&local_8);
  }
  *(undefined4 *)(param_1 + 2) = 0;
  param_1[1] = 0;
  return;
}



void FUN_7101527d78(undefined8 *param_1)

{
  long *plVar1;
  undefined8 *local_8;
  
  *param_1 = &DAT_710395e338;
  local_8 = param_1;
  if ((long *)param_1[1] != (long *)0x0) {
    FUN_7101527df0((long *)param_1[1],&local_8);
  }
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
  }
  else {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    }
  }
  return;
}



void FUN_7101527df0(long *param_1,undefined8 param_2)

{
  long *plVar1;
  
  do {
    if ((long *)*param_1 != (long *)0x0) {
      FUN_7101527df0((long *)*param_1,param_2);
    }
    plVar1 = (long *)param_1[1];
    param_1[5] = 0;
    *param_1 = 0;
    param_1[1] = 0;
    param_1 = plVar1;
  } while (plVar1 != (long *)0x0);
  return;
}



undefined8 FUN_7101527e44(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a5b728 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5b728), iVar1 != 0))
  {
    *DAT_7103a5b720 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5b728);
  }
  if (param_2 != DAT_7103a5b720) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101527f44(void)

{
  int iVar1;
  
  if (((*DAT_7103a5b728 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5b728), iVar1 != 0))
  {
    *DAT_7103a5b720 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5b728);
  }
  return DAT_7103a5b720;
}



void FUN_7101527fa8(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101527fe8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_71015288c8(void)

{
  int iVar1;
  
  if (((*DAT_7103a60d78 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60d78), iVar1 != 0))
  {
    *DAT_7103a60d70 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60d78);
  }
  return DAT_7103a60d70;
}



void FUN_710152892c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152896c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101529248(void)

{
  int iVar1;
  
  if (((*DAT_7103a62098 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62098), iVar1 != 0))
  {
    *DAT_7103a62090 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62098);
  }
  return DAT_7103a62090;
}



void FUN_71015292ac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015292ec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101529bc8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c4a0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c4a0), iVar1 != 0))
  {
    *DAT_7103a5c498 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c4a0);
  }
  return DAT_7103a5c498;
}



void FUN_7101529c2c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101529c6c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152a548(void)

{
  int iVar1;
  
  if (((*DAT_7103a5d4a8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5d4a8), iVar1 != 0))
  {
    *DAT_7103a5d4a0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5d4a8);
  }
  return DAT_7103a5d4a0;
}



void FUN_710152a5ac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152a5ec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152aec8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5d258 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5d258), iVar1 != 0))
  {
    *DAT_7103a5d250 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5d258);
  }
  return DAT_7103a5d250;
}



void FUN_710152af2c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152af6c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152b848(void)

{
  int iVar1;
  
  if (((*DAT_7103a5d2a0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5d2a0), iVar1 != 0))
  {
    *DAT_7103a5d298 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5d2a0);
  }
  return DAT_7103a5d298;
}



void FUN_710152b8ac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152b8ec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152c1c8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c9a8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c9a8), iVar1 != 0))
  {
    *DAT_7103a5c9a0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c9a8);
  }
  return DAT_7103a5c9a0;
}



void FUN_710152c22c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152c26c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152cb48(void)

{
  int iVar1;
  
  if (((*DAT_7103a609a0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a609a0), iVar1 != 0))
  {
    *DAT_7103a60998 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a609a0);
  }
  return DAT_7103a60998;
}



void FUN_710152cbac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152cbec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152d4c8(void)

{
  int iVar1;
  
  if (((*DAT_7103a61918 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a61918), iVar1 != 0))
  {
    *DAT_7103a61910 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a61918);
  }
  return DAT_7103a61910;
}



void FUN_710152d52c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152d56c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152de48(void)

{
  int iVar1;
  
  if (((*DAT_7103a621e8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a621e8), iVar1 != 0))
  {
    *DAT_7103a621e0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a621e8);
  }
  return DAT_7103a621e0;
}



void FUN_710152deac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152deec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152e7c8(void)

{
  int iVar1;
  
  if (((*DAT_7103a62220 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62220), iVar1 != 0))
  {
    *DAT_7103a62218 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62220);
  }
  return DAT_7103a62218;
}



void FUN_710152e82c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152e86c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152f148(void)

{
  int iVar1;
  
  if (((*DAT_7103a5bf20 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5bf20), iVar1 != 0))
  {
    *DAT_7103a5bf18 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5bf20);
  }
  return DAT_7103a5bf18;
}



void FUN_710152f1ac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152f1ec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710152fac8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5d818 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5d818), iVar1 != 0))
  {
    *DAT_7103a5d810 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5d818);
  }
  return DAT_7103a5d810;
}



void FUN_710152fb2c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710152fb6c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101530448(void)

{
  int iVar1;
  
  if (((*DAT_7103a5e588 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5e588), iVar1 != 0))
  {
    *DAT_7103a5e580 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5e588);
  }
  return DAT_7103a5e580;
}



void FUN_71015304ac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015304ec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101530dc8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c4f8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c4f8), iVar1 != 0))
  {
    *DAT_7103a5c4f0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c4f8);
  }
  return DAT_7103a5c4f0;
}



void FUN_7101530e2c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101530e6c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101531748(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c518 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c518), iVar1 != 0))
  {
    *DAT_7103a5c510 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c518);
  }
  return DAT_7103a5c510;
}



void FUN_71015317ac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015317ec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_71015320c8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c538 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c538), iVar1 != 0))
  {
    *DAT_7103a5c530 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c538);
  }
  return DAT_7103a5c530;
}



void FUN_710153212c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153216c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101532a48(void)

{
  int iVar1;
  
  if (((*DAT_7103a60ad0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60ad0), iVar1 != 0))
  {
    *DAT_7103a60ac8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60ad0);
  }
  return DAT_7103a60ac8;
}



void FUN_7101532aac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101532aec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_71015333c8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a508 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a508), iVar1 != 0))
  {
    *DAT_7103a5a500 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a508);
  }
  return DAT_7103a5a500;
}



void FUN_710153342c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153346c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101533d48(void)

{
  int iVar1;
  
  if (((*DAT_7103a623a0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a623a0), iVar1 != 0))
  {
    *DAT_7103a62398 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a623a0);
  }
  return DAT_7103a62398;
}



void FUN_7101533dac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101533dec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_71015346c8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5cff0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5cff0), iVar1 != 0))
  {
    *DAT_7103a5cfe8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5cff0);
  }
  return DAT_7103a5cfe8;
}



void FUN_710153472c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153476c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101535048(void)

{
  int iVar1;
  
  if (((*DAT_7103a62400 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62400), iVar1 != 0))
  {
    *DAT_7103a623f8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62400);
  }
  return DAT_7103a623f8;
}



void FUN_71015350ac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015350ec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_71015359c8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5b948 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5b948), iVar1 != 0))
  {
    *DAT_7103a5b940 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5b948);
  }
  return DAT_7103a5b940;
}



void FUN_7101535a2c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101535a6c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 * FUN_710153633c(void)

{
  int iVar1;
  
  if (((DAT_7104079a40 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_7104079a40), iVar1 != 0))
  {
    DAT_7104079a38 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_7104079a40);
  }
  return &DAT_7104079a38;
}



void FUN_710153639c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015363dc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101536cb8(void)

{
  int iVar1;
  
  if (((*DAT_7103a62498 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62498), iVar1 != 0))
  {
    *DAT_7103a62490 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62498);
  }
  return DAT_7103a62490;
}



void FUN_7101536d1c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101536d5c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101537638(void)

{
  int iVar1;
  
  if (((*DAT_7103a624d0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a624d0), iVar1 != 0))
  {
    *DAT_7103a624c8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a624d0);
  }
  return DAT_7103a624c8;
}



void FUN_710153769c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015376dc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101537fb8(void)

{
  int iVar1;
  
  if (((*DAT_7103a62508 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62508), iVar1 != 0))
  {
    *DAT_7103a62500 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62508);
  }
  return DAT_7103a62500;
}



void FUN_710153801c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153805c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101538938(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c068 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c068), iVar1 != 0))
  {
    *DAT_7103a5c060 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c068);
  }
  return DAT_7103a5c060;
}



void FUN_710153899c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015389dc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_71015392b8(void)

{
  int iVar1;
  
  if (((*DAT_7103a608e0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a608e0), iVar1 != 0))
  {
    *DAT_7103a608d8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a608e0);
  }
  return DAT_7103a608d8;
}



void FUN_710153931c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153935c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101539c38(void)

{
  int iVar1;
  
  if (((*DAT_7103a5e1b0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5e1b0), iVar1 != 0))
  {
    *DAT_7103a5e1a8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5e1b0);
  }
  return DAT_7103a5e1a8;
}



void FUN_7101539c9c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101539cdc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710153a5b8(void)

{
  int iVar1;
  
  if (((*DAT_7103a625c0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a625c0), iVar1 != 0))
  {
    *DAT_7103a625b8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a625c0);
  }
  return DAT_7103a625b8;
}



void FUN_710153a61c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153a65c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710153af38(void)

{
  int iVar1;
  
  if (((*DAT_7103a60978 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60978), iVar1 != 0))
  {
    *DAT_7103a60970 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60978);
  }
  return DAT_7103a60970;
}



void FUN_710153af9c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153afdc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710153b8b8(void)

{
  int iVar1;
  
  if (((*DAT_7103a60930 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60930), iVar1 != 0))
  {
    *DAT_7103a60928 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60930);
  }
  return DAT_7103a60928;
}



void FUN_710153b91c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153b95c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710153c238(void)

{
  int iVar1;
  
  if (((*DAT_7103a60ed8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60ed8), iVar1 != 0))
  {
    *DAT_7103a60ed0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60ed8);
  }
  return DAT_7103a60ed0;
}



void FUN_710153c29c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153c2dc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710153cbb8(void)

{
  int iVar1;
  
  if (((*DAT_7103a616e8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a616e8), iVar1 != 0))
  {
    *DAT_7103a616e0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a616e8);
  }
  return DAT_7103a616e0;
}



void FUN_710153cc1c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153cc5c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710153d538(void)

{
  int iVar1;
  
  if (((*DAT_7103a62698 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62698), iVar1 != 0))
  {
    *DAT_7103a62690 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62698);
  }
  return DAT_7103a62690;
}



void FUN_710153d59c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153d5dc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710153deb8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c120 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c120), iVar1 != 0))
  {
    *DAT_7103a5c118 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c120);
  }
  return DAT_7103a5c118;
}



void FUN_710153df1c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153df5c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 * FUN_710153e82c(void)

{
  int iVar1;
  
  if (((DAT_7104079d40 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_7104079d40), iVar1 != 0))
  {
    DAT_7104079d38 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_7104079d40);
  }
  return &DAT_7104079d38;
}



void FUN_710153e88c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153e8cc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 * FUN_710153f19c(void)

{
  int iVar1;
  
  if (((DAT_7104079d60 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_7104079d60), iVar1 != 0))
  {
    DAT_7104079d58 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_7104079d60);
  }
  return &DAT_7104079d58;
}



void FUN_710153f1fc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153f23c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 FUN_710153f980(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a617e0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a617e0), iVar1 != 0))
  {
    *DAT_7103a617d8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a617e0);
  }
  if (param_2 != DAT_7103a617d8) {
    if (((*DAT_7103a59e90 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e90), iVar1 != 0)
       ) {
      *DAT_7103a59e88 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a59e90);
    }
    if (param_2 != DAT_7103a59e88) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_710153fa80(void)

{
  int iVar1;
  
  if (((*DAT_7103a617e0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a617e0), iVar1 != 0))
  {
    *DAT_7103a617d8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a617e0);
  }
  return DAT_7103a617d8;
}



void FUN_710153fae4(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710153fb24. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101540408(void)

{
  int iVar1;
  
  if (((*DAT_7103a5e5a8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5e5a8), iVar1 != 0))
  {
    *DAT_7103a5e5a0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5e5a8);
  }
  return DAT_7103a5e5a0;
}



void FUN_710154046c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015404ac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101540d88(void)

{
  int iVar1;
  
  if (((*DAT_7103a60a60 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60a60), iVar1 != 0))
  {
    *DAT_7103a60a58 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60a60);
  }
  return DAT_7103a60a58;
}



void FUN_7101540dec(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101540e2c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101541708(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c0b8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c0b8), iVar1 != 0))
  {
    *DAT_7103a5c0b0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c0b8);
  }
  return DAT_7103a5c0b0;
}



void FUN_710154176c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015417ac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101542088(void)

{
  int iVar1;
  
  if (((*DAT_7103a5d6a8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5d6a8), iVar1 != 0))
  {
    *DAT_7103a5d6a0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5d6a8);
  }
  return DAT_7103a5d6a0;
}



void FUN_71015420ec(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154212c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101542a08(void)

{
  int iVar1;
  
  if (((*DAT_7103a627e8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a627e8), iVar1 != 0))
  {
    *DAT_7103a627e0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a627e8);
  }
  return DAT_7103a627e0;
}



void FUN_7101542a6c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101542aac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101543388(void)

{
  int iVar1;
  
  if (((*DAT_7103a62820 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62820), iVar1 != 0))
  {
    *DAT_7103a62818 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62820);
  }
  return DAT_7103a62818;
}



void FUN_71015433ec(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154342c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101543d08(void)

{
  int iVar1;
  
  if (((*DAT_7103a62858 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62858), iVar1 != 0))
  {
    *DAT_7103a62850 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62858);
  }
  return DAT_7103a62850;
}



void FUN_7101543d6c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101543dac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101544688(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c1b8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c1b8), iVar1 != 0))
  {
    *DAT_7103a5c1b0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c1b8);
  }
  return DAT_7103a5c1b0;
}



void FUN_71015446ec(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154472c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101545008(void)

{
  int iVar1;
  
  if (((*DAT_7103a609c0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a609c0), iVar1 != 0))
  {
    *DAT_7103a609b8 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a609c0);
  }
  return DAT_7103a609b8;
}



void FUN_710154506c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015450ac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101545988(void)

{
  int iVar1;
  
  if (((*DAT_7103a60b80 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60b80), iVar1 != 0))
  {
    *DAT_7103a60b78 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60b80);
  }
  return DAT_7103a60b78;
}



void FUN_71015459ec(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101545a2c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101546308(void)

{
  int iVar1;
  
  if (((*DAT_7103a62908 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62908), iVar1 != 0))
  {
    *DAT_7103a62900 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62908);
  }
  return DAT_7103a62900;
}



void FUN_710154636c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015463ac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101546c88(void)

{
  int iVar1;
  
  if (((*DAT_7103a5e190 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5e190), iVar1 != 0))
  {
    *DAT_7103a5e188 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5e190);
  }
  return DAT_7103a5e188;
}



void FUN_7101546cec(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101546d2c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101547608(void)

{
  int iVar1;
  
  if (((*DAT_7103a59e78 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59e78), iVar1 != 0))
  {
    *DAT_7103a59e70 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a59e78);
  }
  return DAT_7103a59e70;
}



void FUN_710154766c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015476ac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined4 * FUN_7101547de4(undefined8 param_1,long *param_2,undefined4 param_3,long param_4)

{
  undefined8 *puVar1;
  long lVar2;
  undefined4 *puVar3;
  long lVar4;
  
  lVar4 = *DAT_7103a65db8;
  if (lVar4 == 0) {
    puVar3 = (undefined4 *)FUN_71005fbcb0(8,0x418);
  }
  else {
    if (param_2 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar4 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      param_2 = (long *)*puVar1;
    }
    puVar3 = (undefined4 *)(**(code **)(*param_2 + 0x30))(param_2,0x418,8);
  }
  FUN_7101583490(puVar3,param_3,param_4);
  return puVar3;
}



void FUN_7101547e88(undefined8 param_1,long param_2)

{
  long *plVar1;
  
  if (param_2 != 0) {
    if (*DAT_7103a65db8 == 0) {
      FUN_71005fbbd0(param_2);
      return;
    }
    plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_2);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101547ecc. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_2);
      return;
    }
  }
  return;
}



long * FUN_7101548084(void)

{
  int iVar1;
  
  if (((*DAT_7103a629a8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a629a8), iVar1 != 0))
  {
    *DAT_7103a629a0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a629a8);
  }
  return DAT_7103a629a0;
}



void FUN_71015480e8(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101548128. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101548a08(void)

{
  int iVar1;
  
  if (((*DAT_7103a5e908 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5e908), iVar1 != 0))
  {
    *DAT_7103a5e900 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5e908);
  }
  return DAT_7103a5e900;
}



void FUN_7101548a6c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101548aac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_7101549388(void)

{
  int iVar1;
  
  if (((*DAT_7103a62a08 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62a08), iVar1 != 0))
  {
    *DAT_7103a62a00 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62a08);
  }
  return DAT_7103a62a00;
}



void FUN_71015493ec(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154942c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 * FUN_7101549cfc(void)

{
  int iVar1;
  
  if (((DAT_710407a110 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710407a110), iVar1 != 0))
  {
    DAT_710407a108 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710407a110);
  }
  return &DAT_710407a108;
}



void FUN_7101549d5c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101549d9c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710154a678(void)

{
  int iVar1;
  
  if (((*DAT_7103a62a68 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62a68), iVar1 != 0))
  {
    *DAT_7103a62a60 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62a68);
  }
  return DAT_7103a62a60;
}



void FUN_710154a6dc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154a71c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710154aff8(void)

{
  int iVar1;
  
  if (((*DAT_7103a5c460 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5c460), iVar1 != 0))
  {
    *DAT_7103a5c458 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c460);
  }
  return DAT_7103a5c458;
}



void FUN_710154b058(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154b098. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710154b83c(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a388 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a388), iVar1 != 0))
  {
    *DAT_7103a5a380 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a388);
  }
  return DAT_7103a5a380;
}



void FUN_710154b89c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154b8dc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710154c07c(void)

{
  int iVar1;
  
  if (((*DAT_7103a5f1b8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5f1b8), iVar1 != 0))
  {
    *DAT_7103a5f1b0 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5f1b8);
  }
  return DAT_7103a5f1b0;
}



void FUN_710154c0dc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154c11c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710154c8bc(void)

{
  int iVar1;
  
  if (((*DAT_7103a60880 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a60880), iVar1 != 0))
  {
    *DAT_7103a60878 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a60880);
  }
  return DAT_7103a60878;
}



void FUN_710154c91c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154c95c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710154d0fc(void)

{
  int iVar1;
  
  if (((*DAT_7103a5a360 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a360), iVar1 != 0))
  {
    *DAT_7103a5a358 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5a360);
  }
  return DAT_7103a5a358;
}



void FUN_710154d15c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154d19c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710154da38(void)

{
  int iVar1;
  
  if (((*DAT_7103a59fa0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a59fa0), iVar1 != 0))
  {
    *DAT_7103a59f98 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a59fa0);
  }
  return DAT_7103a59f98;
}



void FUN_710154da9c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154dadc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_710154e3b8(void)

{
  int iVar1;
  
  if (((*DAT_7103a617a0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a617a0), iVar1 != 0))
  {
    *DAT_7103a61798 = DAT_7103a59e80 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a617a0);
  }
  return DAT_7103a61798;
}



void FUN_710154e41c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00710154e45c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_710154ec40(uint *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined8 *puVar7;
  long lVar8;
  undefined8 uVar9;
  
  *param_1 = param_2;
  param_1[2] = 0;
  param_1[3] = 0;
  if (param_2 != 0) {
    puVar7 = *(undefined8 **)(*DAT_7103a59ec8 + 0xa8);
    if ((*DAT_7103a61c30 & 1) == 0) {
      iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a61c30);
      if (iVar6 != 0) {
        *DAT_7103a61c28 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a61c30);
      }
    }
    lVar8 = (**(code **)*puVar7)(puVar7,DAT_7103a61c28);
    uVar1 = *param_1;
    if ((uVar1 != 0) && (uVar2 = *(uint *)(lVar8 + 0x2c), uVar2 != 0)) {
      uVar4 = 0;
      if (uVar2 != 0) {
        uVar4 = uVar1 / uVar2;
      }
      uVar4 = uVar1 - uVar4 * uVar2;
      uVar5 = uVar4;
      do {
        uVar3 = *(uint *)(*(long *)(lVar8 + 0x20) +
                         (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
        if (uVar3 == uVar1) {
          uVar9 = *(undefined8 *)(*(long *)(lVar8 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
          goto LAB_710154ece0;
        }
        if (uVar3 == 0) break;
        uVar3 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar3 = uVar5 + 1;
        }
        uVar5 = uVar3;
      } while (uVar3 != uVar4);
    }
  }
  uVar9 = 0;
LAB_710154ece0:
  *(undefined8 *)(param_1 + 2) = uVar9;
  return;
}



undefined8 FUN_710154efe0(long param_1,long *param_2)

{
  uint uVar1;
  uint uVar2;
  short sVar3;
  bool bVar4;
  long lVar5;
  short *psVar6;
  char *pcVar7;
  char *pcVar8;
  ulong uVar9;
  uint uVar10;
  uint uVar11;
  undefined1 auVar12 [16];
  undefined8 uStack_50;
  uint uStack_48;
  byte bStack_44;
  
  lVar5 = *(long *)(param_1 + 8);
  if ((lVar5 == 0) || (*(char *)(lVar5 + 0x1ed) == '\0')) {
    return 0;
  }
  if ((*(byte *)(lVar5 + 0x134) & 0xf7) == 0xc0) {
    psVar6 = *(short **)(lVar5 + 0x128);
    uStack_48 = (uint)((ulong)*(undefined8 *)(lVar5 + 0x12d) >> 0x18);
    bStack_44 = (byte)((ulong)*(undefined8 *)(lVar5 + 0x12d) >> 0x38);
    uStack_50._0_5_ = SUB85(psVar6,0);
    uStack_50._5_3_ = (undefined3)((ulong)psVar6 >> 0x28);
    if (((((bStack_44 & 0xf7) == 0xc0) || (bStack_44 == 0xc1)) || (bStack_44 == 0xc4)) ||
       ((bStack_44 & 0xe0) == 0x20)) {
      uVar2 = *(uint *)((long)psVar6 + (ulong)uStack_48);
      uVar11 = uVar2 >> 8;
      uVar10 = uVar11;
      if (*psVar6 == 0x5942) {
        uVar10 = uVar11 & 0xff00 | uVar2 >> 0x18 | (uVar11 & 0xff) << 0x10;
      }
      if (uVar10 != 0) {
        if ((((bStack_44 & 0xf7) == 0xc0) || (bStack_44 == 0xc1)) ||
           ((bStack_44 == 0xc4 || ((bStack_44 & 0xe0) == 0x20)))) {
          if (*psVar6 == 0x5942) {
            uVar11 = uVar11 & 0xff00 | uVar2 >> 0x18 | (uVar11 & 0xff) << 0x10;
          }
          if (uVar11 != 0) {
            uVar10 = 0;
            do {
              auVar12 = FUN_71028132dc(&uStack_50,uVar10);
              psVar6 = auVar12._0_8_;
              pcVar7 = "";
              if ((auVar12._8_8_ & 0xff00000000) == 0xa000000000) {
                sVar3 = *psVar6;
                uVar1 = *(uint *)(psVar6 + 4);
                uVar2 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                uVar2 = uVar2 >> 0x10 | uVar2 << 0x10;
                if (sVar3 != 0x5942) {
                  uVar2 = uVar1;
                }
                if (uVar2 == 0) {
                  pcVar7 = "";
                }
                else {
                  pcVar7 = (char *)((long)psVar6 + (long)(int)uVar2);
                  if (*pcVar7 == -0x3b) {
                    uVar1 = *(uint *)(pcVar7 + 4);
                    uVar2 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                    uVar2 = uVar2 >> 0x10 | uVar2 << 0x10;
                    if (sVar3 != 0x5942) {
                      uVar2 = uVar1;
                    }
                    lVar5 = *(long *)(pcVar7 + uVar2);
                  }
                  else {
                    lVar5 = 0;
                  }
                  uVar1 = *(uint *)(pcVar7 + ((long)(auVar12._8_8_ << 0x20) >> 0x1e) + 4);
                  uVar2 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                  uVar2 = uVar2 >> 0x10 | uVar2 << 0x10;
                  if (sVar3 != 0x5942) {
                    uVar2 = uVar1;
                  }
                  pcVar7 = pcVar7 + (ulong)uVar2 + lVar5;
                }
              }
              *(undefined1 *)((long)(int)param_2[1] + *param_2 + -1) = 0;
              pcVar8 = (char *)*param_2;
              if (pcVar7 == pcVar8) {
                return 1;
              }
              bVar4 = true;
              for (uVar9 = 0; pcVar7[uVar9] == pcVar8[uVar9]; uVar9 = uVar9 + 2) {
                if (pcVar7[uVar9] == '\0') {
LAB_710154f0f0:
                  if (bVar4) {
                    return 1;
                  }
                  break;
                }
                if ((uVar9 == 0x400000) || (pcVar7[uVar9 + 1] != pcVar8[uVar9 + 1])) break;
                if (pcVar7[uVar9 + 1] == '\0') {
                  bVar4 = uVar9 < 0x400000;
                  goto LAB_710154f0f0;
                }
                bVar4 = uVar9 + 1 < 0x400000;
              }
              uVar10 = uVar10 + 1;
            } while (uVar11 != uVar10);
          }
        }
        return 0;
      }
    }
  }
  return 1;
}



undefined4 FUN_710154f220(long param_1,long *param_2)

{
  uint uVar1;
  short sVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  uint uVar6;
  long lVar7;
  char *pcVar8;
  short *psVar9;
  char *pcVar10;
  ulong uVar11;
  uint uVar12;
  uint uVar13;
  undefined1 auVar14 [16];
  short *local_98;
  uint local_90;
  undefined1 local_8c;
  undefined *local_88;
  long local_80;
  undefined4 local_78;
  undefined1 local_74;
  undefined8 uStack_70;
  uint uStack_68;
  byte bStack_64;
  
  lVar7 = *(long *)(param_1 + 8);
  if (lVar7 == 0) {
    return 0xffffffff;
  }
  if ((*(byte *)(lVar7 + 0x144) & 0xf7) == 0xc0) {
    uStack_68 = (uint)((ulong)*(undefined8 *)(lVar7 + 0x13d) >> 0x18);
    bStack_64 = (byte)((ulong)*(undefined8 *)(lVar7 + 0x13d) >> 0x38);
    psVar9 = *(short **)(lVar7 + 0x138);
    uStack_70._0_5_ = SUB85(psVar9,0);
    uStack_70._5_3_ = (undefined3)((ulong)psVar9 >> 0x28);
    if (((((bStack_64 & 0xf7) == 0xc0) || (bStack_64 == 0xc1)) || (bStack_64 == 0xc4)) ||
       ((bStack_64 & 0xe0) == 0x20)) {
      uVar3 = *(uint *)((long)psVar9 + (ulong)uStack_68) >> 8;
      if (*psVar9 == 0x5942) {
        uVar3 = uVar3 & 0xff00 | *(uint *)((long)psVar9 + (ulong)uStack_68) >> 0x18 |
                (uVar3 & 0xff) << 0x10;
      }
      if (uVar3 != 0) {
        uVar12 = 0;
        do {
          local_78 = 0;
          local_74 = 0;
          local_88 = &DAT_710395e620;
          local_80 = 0;
          auVar14 = FUN_71028132dc(&uStack_70,uVar12);
          if ((auVar14._0_8_ != 0) &&
             ((uVar6 = auVar14._12_4_ & 0xff, uVar6 == 0xc4 || (uVar6 == 0xc1)))) {
            local_78 = auVar14._8_4_;
            local_74 = auVar14[0xc];
            local_80 = auVar14._0_8_;
          }
          auVar14 = FUN_7102813520(&local_80,"ForkStrMainAry");
          psVar9 = auVar14._0_8_;
          if ((psVar9 != (short *)0x0) && ((auVar14._8_8_ & 0xf700000000) == 0xc000000000)) {
            uVar6 = auVar14._12_4_;
            local_8c = auVar14[0xc];
            local_90 = auVar14._8_4_;
            local_98 = psVar9;
            if (((uVar6 & 0xf7) == 0xc0) ||
               ((((uVar6 & 0xff) == 0xc1 || ((uVar6 & 0xff) == 0xc4)) || ((uVar6 & 0xe0) == 0x20))))
            {
              uVar6 = *(uint *)((long)psVar9 + (ulong)local_90) >> 8;
              if (*psVar9 == 0x5942) {
                uVar6 = uVar6 & 0xff00 | *(uint *)((long)psVar9 + (ulong)local_90) >> 0x18 |
                        (uVar6 & 0xff) << 0x10;
              }
              if (uVar6 != 0) {
                uVar13 = 0;
                do {
                  auVar14 = FUN_71028132dc(&local_98,uVar13);
                  psVar9 = auVar14._0_8_;
                  pcVar8 = "";
                  if ((auVar14._8_8_ & 0xff00000000) == 0xa000000000) {
                    sVar2 = *psVar9;
                    uVar1 = *(uint *)(psVar9 + 4);
                    uVar4 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                    uVar4 = uVar4 >> 0x10 | uVar4 << 0x10;
                    if (sVar2 != 0x5942) {
                      uVar4 = uVar1;
                    }
                    if (uVar4 == 0) {
                      pcVar8 = "";
                    }
                    else {
                      pcVar8 = (char *)((long)psVar9 + (long)(int)uVar4);
                      if (*pcVar8 == -0x3b) {
                        uVar1 = *(uint *)(pcVar8 + 4);
                        uVar4 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                        uVar4 = uVar4 >> 0x10 | uVar4 << 0x10;
                        if (sVar2 != 0x5942) {
                          uVar4 = uVar1;
                        }
                        lVar7 = *(long *)(pcVar8 + uVar4);
                      }
                      else {
                        lVar7 = 0;
                      }
                      uVar1 = *(uint *)(pcVar8 + ((long)(auVar14._8_8_ << 0x20) >> 0x1e) + 4);
                      uVar4 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                      uVar4 = uVar4 >> 0x10 | uVar4 << 0x10;
                      if (sVar2 != 0x5942) {
                        uVar4 = uVar1;
                      }
                      pcVar8 = pcVar8 + (ulong)uVar4 + lVar7;
                    }
                  }
                  *(undefined1 *)((long)(int)param_2[1] + *param_2 + -1) = 0;
                  pcVar10 = (char *)*param_2;
                  if (pcVar8 == pcVar10) {
LAB_710154f4f0:
                    auVar14 = FUN_7102813520(&local_80,"SkipRestartCameraChangeCount");
                    if ((auVar14._8_8_ & 0xff00000000) == 0xd100000000) {
                      return auVar14._8_4_;
                    }
                    return 0xffffffff;
                  }
                  bVar5 = true;
                  for (uVar11 = 0; pcVar8[uVar11] == pcVar10[uVar11]; uVar11 = uVar11 + 2) {
                    if (pcVar8[uVar11] == '\0') {
LAB_710154f3e8:
                      if (bVar5) goto LAB_710154f4f0;
                      break;
                    }
                    if ((uVar11 == 0x400000) || (pcVar8[uVar11 + 1] != pcVar10[uVar11 + 1])) break;
                    if (pcVar8[uVar11 + 1] == '\0') {
                      bVar5 = uVar11 < 0x400000;
                      goto LAB_710154f3e8;
                    }
                    bVar5 = uVar11 + 1 < 0x400000;
                  }
                  uVar13 = uVar13 + 1;
                } while (uVar6 != uVar13);
              }
            }
          }
          uVar12 = uVar12 + 1;
        } while (uVar3 != uVar12);
        lVar7 = *(long *)(param_1 + 8);
      }
    }
  }
  return *(undefined4 *)(lVar7 + 0x1c8);
}



void FUN_710154f550(undefined8 *param_1,long param_2,long *param_3)

{
  char *pcVar1;
  uint uVar2;
  short sVar3;
  uint uVar4;
  ulong uVar5;
  uint uVar6;
  uint uVar7;
  short *psVar8;
  ulong uVar9;
  char *pcVar10;
  long lVar11;
  char *pcVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  undefined1 auVar16 [16];
  short *local_98;
  uint local_90;
  undefined1 local_8c;
  undefined *local_88;
  long local_80;
  undefined4 local_78;
  uint local_74;
  undefined8 uStack_70;
  uint uStack_68;
  byte bStack_64;
  
  lVar11 = *(long *)(param_2 + 8);
  if ((lVar11 != 0) && ((*(byte *)(lVar11 + 0x114) & 0xf7) == 0xc0)) {
    psVar8 = *(short **)(lVar11 + 0x108);
    uStack_68 = (uint)((ulong)*(undefined8 *)(lVar11 + 0x10d) >> 0x18);
    bStack_64 = (byte)((ulong)*(undefined8 *)(lVar11 + 0x10d) >> 0x38);
    uStack_70._0_5_ = SUB85(psVar8,0);
    uStack_70._5_3_ = (undefined3)((ulong)psVar8 >> 0x28);
    if (((bStack_64 & 0xf7) == 0xc0) ||
       (((bStack_64 == 0xc1 || (bStack_64 == 0xc4)) || ((bStack_64 & 0xe0) == 0x20)))) {
      uVar4 = *(uint *)((long)psVar8 + (ulong)uStack_68) >> 8;
      if (*psVar8 == 0x5942) {
        uVar4 = uVar4 & 0xff00 | *(uint *)((long)psVar8 + (ulong)uStack_68) >> 0x18 |
                (uVar4 & 0xff) << 0x10;
      }
      if (uVar4 != 0) {
        uVar14 = 0;
        pcVar1 = "";
        do {
          local_78 = 0;
          local_74 = local_74 & 0xffffff00;
          local_88 = &DAT_710395e640;
          local_80 = 0;
          auVar16 = FUN_71028132dc(&uStack_70,uVar14);
          if ((auVar16._0_8_ != 0) &&
             ((uVar6 = auVar16._12_4_ & 0xff, uVar6 == 0xc4 || (uVar6 == 0xc1)))) {
            local_78 = auVar16._8_4_;
            local_74 = CONCAT31(local_74._1_3_,auVar16[0xc]);
            local_80 = auVar16._0_8_;
          }
          auVar16 = FUN_7102813520(&local_80,"ForkStrMainAry");
          psVar8 = auVar16._0_8_;
          if ((psVar8 == (short *)0x0) || ((auVar16._8_8_ & 0xf700000000) != 0xc000000000)) {
LAB_710154f8b0:
            auVar16 = FUN_7102813520(&local_80,"ForkStrSub1Ary");
            psVar8 = auVar16._0_8_;
            if ((psVar8 != (short *)0x0) && ((auVar16._8_8_ & 0xf700000000) == 0xc000000000)) {
              uVar6 = auVar16._12_4_;
              local_8c = auVar16[0xc];
              local_90 = auVar16._8_4_;
              if (((uVar6 & 0xf7) == 0xc0) ||
                 ((((uVar6 & 0xff) == 0xc1 || ((uVar6 & 0xff) == 0xc4)) ||
                  (local_98 = psVar8, (uVar6 & 0xe0) == 0x20)))) {
                uVar6 = *(uint *)((long)psVar8 + (ulong)local_90) >> 8;
                if (*psVar8 == 0x5942) {
                  uVar6 = uVar6 & 0xff00 | *(uint *)((long)psVar8 + (ulong)local_90) >> 0x18 |
                          (uVar6 & 0xff) << 0x10;
                }
                local_98 = psVar8;
                if (uVar6 != 0) {
                  uVar13 = 0;
                  uVar15 = 0;
                  do {
                    auVar16 = FUN_71028132dc(&local_98,uVar15);
                    psVar8 = auVar16._0_8_;
                    pcVar12 = pcVar1;
                    if ((auVar16._8_8_ & 0xff00000000) == 0xa000000000) {
                      sVar3 = *psVar8;
                      uVar2 = *(uint *)(psVar8 + 4);
                      uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                      uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                      if (sVar3 != 0x5942) {
                        uVar7 = uVar2;
                      }
                      if (uVar7 == 0) {
                        pcVar12 = "";
                      }
                      else {
                        pcVar12 = (char *)((long)psVar8 + (long)(int)uVar7);
                        if (*pcVar12 == -0x3b) {
                          uVar2 = *(uint *)(pcVar12 + 4);
                          uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                          uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                          if (sVar3 != 0x5942) {
                            uVar7 = uVar2;
                          }
                          lVar11 = *(long *)(pcVar12 + uVar7);
                        }
                        else {
                          lVar11 = 0;
                        }
                        uVar2 = *(uint *)(pcVar12 + ((long)(auVar16._8_8_ << 0x20) >> 0x1e) + 4);
                        uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                        uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                        if (sVar3 != 0x5942) {
                          uVar7 = uVar2;
                        }
                        pcVar12 = pcVar12 + (ulong)uVar7 + lVar11;
                      }
                    }
                    *(undefined1 *)((long)(int)param_3[0xb] + param_3[10] + -1) = 0;
                    if ((char *)param_3[10] == pcVar12) {
LAB_710154f954:
                      uVar7 = 3;
                    }
                    else {
                      ((char *)param_3[10])[(long)(int)param_3[0xb] + -1] = '\0';
                      pcVar10 = (char *)param_3[10];
                      uVar7 = 5;
                      if (*pcVar10 == *pcVar12) {
                        if (*pcVar10 != '\0') {
                          uVar5 = 0;
                          do {
                            uVar9 = uVar5;
                            if ((uVar9 == 0x400000) || (pcVar10[uVar9 + 1] != pcVar12[uVar9 + 1])) {
LAB_710154faac:
                              uVar7 = 5;
                              goto LAB_710154f958;
                            }
                            if (pcVar10[uVar9 + 1] == '\0') goto LAB_710154fac0;
                            if (pcVar10[uVar9 + 2] != pcVar12[uVar9 + 2]) goto LAB_710154faac;
                            if (pcVar10[uVar9 + 2] == '\0') {
                              uVar9 = uVar9 + 1;
                              goto LAB_710154fac0;
                            }
                            if (pcVar10[uVar9 + 3] != pcVar12[uVar9 + 3]) goto LAB_710154faac;
                            if (pcVar10[uVar9 + 3] == '\0') {
                              uVar9 = uVar9 + 2;
                              goto LAB_710154fac0;
                            }
                            if (pcVar10[uVar9 + 4] != pcVar12[uVar9 + 4]) goto LAB_710154faac;
                            uVar5 = uVar9 + 4;
                          } while (pcVar10[uVar9 + 4] != '\0');
                          uVar9 = uVar9 + 3;
LAB_710154fac0:
                          uVar7 = 5;
                          if (uVar9 >> 0x16 != 0) goto LAB_710154f958;
                        }
                        goto LAB_710154f954;
                      }
                    }
LAB_710154f958:
                    uVar15 = uVar15 + 1;
                    uVar13 = uVar7 | uVar13;
                  } while (uVar6 != uVar15);
                  if ((uVar13 & 3) == 1) goto LAB_710154f630;
                }
              }
            }
            auVar16 = FUN_7102813520(&local_80,"ForkStrSub2Ary");
            local_98 = auVar16._0_8_;
            if ((local_98 == (short *)0x0) || ((auVar16._8_8_ & 0xf700000000) != 0xc000000000)) {
LAB_710154fd14:
              param_1[1] = local_80;
              param_1[2] = CONCAT44(local_74,local_78);
              *param_1 = &DAT_710395e640;
              *(undefined1 *)(param_1 + 3) = 1;
              return;
            }
            uVar6 = auVar16._12_4_;
            local_8c = auVar16[0xc];
            local_90 = auVar16._8_4_;
            if (((uVar6 & 0xf7) != 0xc0) &&
               ((((uVar6 & 0xff) != 0xc1 && ((uVar6 & 0xff) != 0xc4)) && ((uVar6 & 0xe0) != 0x20))))
            goto LAB_710154fd14;
            uVar6 = *(uint *)((long)local_98 + (ulong)local_90) >> 8;
            if (*local_98 == 0x5942) {
              uVar6 = uVar6 & 0xff00 | *(uint *)((long)local_98 + (ulong)local_90) >> 0x18 |
                      (uVar6 & 0xff) << 0x10;
            }
            if (uVar6 == 0) goto LAB_710154fd14;
            uVar13 = 0;
            uVar15 = 0;
            do {
              auVar16 = FUN_71028132dc(&local_98,uVar15);
              psVar8 = auVar16._0_8_;
              pcVar12 = pcVar1;
              if ((auVar16._8_8_ & 0xff00000000) == 0xa000000000) {
                sVar3 = *psVar8;
                uVar2 = *(uint *)(psVar8 + 4);
                uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                if (sVar3 != 0x5942) {
                  uVar7 = uVar2;
                }
                if (uVar7 == 0) {
                  pcVar12 = "";
                }
                else {
                  pcVar12 = (char *)((long)psVar8 + (long)(int)uVar7);
                  if (*pcVar12 == -0x3b) {
                    uVar2 = *(uint *)(pcVar12 + 4);
                    uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                    uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                    if (sVar3 != 0x5942) {
                      uVar7 = uVar2;
                    }
                    lVar11 = *(long *)(pcVar12 + uVar7);
                  }
                  else {
                    lVar11 = 0;
                  }
                  uVar2 = *(uint *)(pcVar12 + ((long)(auVar16._8_8_ << 0x20) >> 0x1e) + 4);
                  uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                  uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                  if (sVar3 != 0x5942) {
                    uVar7 = uVar2;
                  }
                  pcVar12 = pcVar12 + (ulong)uVar7 + lVar11;
                }
              }
              *(undefined1 *)((long)(int)param_3[0x15] + param_3[0x14] + -1) = 0;
              if ((char *)param_3[0x14] == pcVar12) {
LAB_710154fb84:
                uVar7 = 3;
              }
              else {
                ((char *)param_3[0x14])[(long)(int)param_3[0x15] + -1] = '\0';
                pcVar10 = (char *)param_3[0x14];
                uVar7 = 5;
                if (*pcVar10 == *pcVar12) {
                  if (*pcVar10 != '\0') {
                    uVar5 = 0;
                    do {
                      uVar9 = uVar5;
                      if ((uVar9 == 0x400000) || (pcVar10[uVar9 + 1] != pcVar12[uVar9 + 1])) {
LAB_710154fcdc:
                        uVar7 = 5;
                        goto LAB_710154fb88;
                      }
                      if (pcVar10[uVar9 + 1] == '\0') goto LAB_710154fcf0;
                      if (pcVar10[uVar9 + 2] != pcVar12[uVar9 + 2]) goto LAB_710154fcdc;
                      if (pcVar10[uVar9 + 2] == '\0') {
                        uVar9 = uVar9 + 1;
                        goto LAB_710154fcf0;
                      }
                      if (pcVar10[uVar9 + 3] != pcVar12[uVar9 + 3]) goto LAB_710154fcdc;
                      if (pcVar10[uVar9 + 3] == '\0') {
                        uVar9 = uVar9 + 2;
                        goto LAB_710154fcf0;
                      }
                      if (pcVar10[uVar9 + 4] != pcVar12[uVar9 + 4]) goto LAB_710154fcdc;
                      uVar5 = uVar9 + 4;
                    } while (pcVar10[uVar9 + 4] != '\0');
                    uVar9 = uVar9 + 3;
LAB_710154fcf0:
                    uVar7 = 5;
                    if (uVar9 >> 0x16 != 0) goto LAB_710154fb88;
                  }
                  goto LAB_710154fb84;
                }
              }
LAB_710154fb88:
              uVar15 = uVar15 + 1;
              uVar13 = uVar7 | uVar13;
            } while (uVar6 != uVar15);
            if ((uVar13 & 3) != 1) goto LAB_710154fd14;
          }
          else {
            uVar6 = auVar16._12_4_;
            local_8c = auVar16[0xc];
            local_90 = auVar16._8_4_;
            local_98 = psVar8;
            if (((uVar6 & 0xf7) != 0xc0) &&
               ((((uVar6 & 0xff) != 0xc1 && ((uVar6 & 0xff) != 0xc4)) && ((uVar6 & 0xe0) != 0x20))))
            goto LAB_710154f8b0;
            uVar6 = *(uint *)((long)psVar8 + (ulong)local_90) >> 8;
            if (*psVar8 == 0x5942) {
              uVar6 = uVar6 & 0xff00 | *(uint *)((long)psVar8 + (ulong)local_90) >> 0x18 |
                      (uVar6 & 0xff) << 0x10;
            }
            if (uVar6 == 0) goto LAB_710154f8b0;
            uVar13 = 0;
            uVar15 = 0;
            do {
              auVar16 = FUN_71028132dc(&local_98,uVar15);
              psVar8 = auVar16._0_8_;
              pcVar12 = pcVar1;
              if ((auVar16._8_8_ & 0xff00000000) == 0xa000000000) {
                sVar3 = *psVar8;
                uVar2 = *(uint *)(psVar8 + 4);
                uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                if (sVar3 != 0x5942) {
                  uVar7 = uVar2;
                }
                if (uVar7 == 0) {
                  pcVar12 = "";
                }
                else {
                  pcVar12 = (char *)((long)psVar8 + (long)(int)uVar7);
                  if (*pcVar12 == -0x3b) {
                    uVar2 = *(uint *)(pcVar12 + 4);
                    uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                    uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                    if (sVar3 != 0x5942) {
                      uVar7 = uVar2;
                    }
                    lVar11 = *(long *)(pcVar12 + uVar7);
                  }
                  else {
                    lVar11 = 0;
                  }
                  uVar2 = *(uint *)(pcVar12 + ((long)(auVar16._8_8_ << 0x20) >> 0x1e) + 4);
                  uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                  uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                  if (sVar3 != 0x5942) {
                    uVar7 = uVar2;
                  }
                  pcVar12 = pcVar12 + (ulong)uVar7 + lVar11;
                }
              }
              *(undefined1 *)((long)(int)param_3[1] + *param_3 + -1) = 0;
              if ((char *)*param_3 == pcVar12) {
LAB_710154f724:
                uVar7 = 3;
              }
              else {
                ((char *)*param_3)[(long)(int)param_3[1] + -1] = '\0';
                pcVar10 = (char *)*param_3;
                uVar7 = 5;
                if (*pcVar10 == *pcVar12) {
                  if (*pcVar10 != '\0') {
                    uVar5 = 0;
                    do {
                      uVar9 = uVar5;
                      if ((uVar9 == 0x400000) || (pcVar10[uVar9 + 1] != pcVar12[uVar9 + 1])) {
LAB_710154f87c:
                        uVar7 = 5;
                        goto LAB_710154f728;
                      }
                      if (pcVar10[uVar9 + 1] == '\0') goto LAB_710154f890;
                      if (pcVar10[uVar9 + 2] != pcVar12[uVar9 + 2]) goto LAB_710154f87c;
                      if (pcVar10[uVar9 + 2] == '\0') {
                        uVar9 = uVar9 + 1;
                        goto LAB_710154f890;
                      }
                      if (pcVar10[uVar9 + 3] != pcVar12[uVar9 + 3]) goto LAB_710154f87c;
                      if (pcVar10[uVar9 + 3] == '\0') {
                        uVar9 = uVar9 + 2;
                        goto LAB_710154f890;
                      }
                      if (pcVar10[uVar9 + 4] != pcVar12[uVar9 + 4]) goto LAB_710154f87c;
                      uVar5 = uVar9 + 4;
                    } while (pcVar10[uVar9 + 4] != '\0');
                    uVar9 = uVar9 + 3;
LAB_710154f890:
                    uVar7 = 5;
                    if (uVar9 >> 0x16 != 0) goto LAB_710154f728;
                  }
                  goto LAB_710154f724;
                }
              }
LAB_710154f728:
              uVar15 = uVar15 + 1;
              uVar13 = uVar7 | uVar13;
            } while (uVar6 != uVar15);
            if ((uVar13 & 3) != 1) goto LAB_710154f8b0;
          }
LAB_710154f630:
          uVar14 = uVar14 + 1;
        } while (uVar4 != uVar14);
      }
    }
  }
  *(undefined1 *)(param_1 + 3) = 0;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



void FUN_710154fd60(undefined8 *param_1,long param_2,long *param_3)

{
  char *pcVar1;
  uint uVar2;
  short sVar3;
  uint uVar4;
  ulong uVar5;
  uint uVar6;
  uint uVar7;
  short *psVar8;
  ulong uVar9;
  char *pcVar10;
  long lVar11;
  char *pcVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  undefined1 auVar16 [16];
  short *local_98;
  uint local_90;
  undefined1 local_8c;
  undefined *local_88;
  long local_80;
  undefined4 local_78;
  uint local_74;
  undefined8 uStack_70;
  uint uStack_68;
  byte bStack_64;
  
  lVar11 = *(long *)(param_2 + 8);
  if ((lVar11 != 0) && ((*(byte *)(lVar11 + 0x154) & 0xf7) == 0xc0)) {
    psVar8 = *(short **)(lVar11 + 0x148);
    uStack_68 = (uint)((ulong)*(undefined8 *)(lVar11 + 0x14d) >> 0x18);
    bStack_64 = (byte)((ulong)*(undefined8 *)(lVar11 + 0x14d) >> 0x38);
    uStack_70._0_5_ = SUB85(psVar8,0);
    uStack_70._5_3_ = (undefined3)((ulong)psVar8 >> 0x28);
    if (((bStack_64 & 0xf7) == 0xc0) ||
       (((bStack_64 == 0xc1 || (bStack_64 == 0xc4)) || ((bStack_64 & 0xe0) == 0x20)))) {
      uVar4 = *(uint *)((long)psVar8 + (ulong)uStack_68) >> 8;
      if (*psVar8 == 0x5942) {
        uVar4 = uVar4 & 0xff00 | *(uint *)((long)psVar8 + (ulong)uStack_68) >> 0x18 |
                (uVar4 & 0xff) << 0x10;
      }
      if (uVar4 != 0) {
        uVar14 = 0;
        pcVar1 = "";
        do {
          local_78 = 0;
          local_74 = local_74 & 0xffffff00;
          local_88 = &DAT_710395e660;
          local_80 = 0;
          auVar16 = FUN_71028132dc(&uStack_70,uVar14);
          if ((auVar16._0_8_ != 0) &&
             ((uVar6 = auVar16._12_4_ & 0xff, uVar6 == 0xc4 || (uVar6 == 0xc1)))) {
            local_78 = auVar16._8_4_;
            local_74 = CONCAT31(local_74._1_3_,auVar16[0xc]);
            local_80 = auVar16._0_8_;
          }
          auVar16 = FUN_7102813520(&local_80,"ForkStrMainAry");
          psVar8 = auVar16._0_8_;
          if ((psVar8 == (short *)0x0) || ((auVar16._8_8_ & 0xf700000000) != 0xc000000000)) {
LAB_71015500c0:
            auVar16 = FUN_7102813520(&local_80,"ForkStrSub1Ary");
            psVar8 = auVar16._0_8_;
            if ((psVar8 != (short *)0x0) && ((auVar16._8_8_ & 0xf700000000) == 0xc000000000)) {
              uVar6 = auVar16._12_4_;
              local_8c = auVar16[0xc];
              local_90 = auVar16._8_4_;
              if (((uVar6 & 0xf7) == 0xc0) ||
                 ((((uVar6 & 0xff) == 0xc1 || ((uVar6 & 0xff) == 0xc4)) ||
                  (local_98 = psVar8, (uVar6 & 0xe0) == 0x20)))) {
                uVar6 = *(uint *)((long)psVar8 + (ulong)local_90) >> 8;
                if (*psVar8 == 0x5942) {
                  uVar6 = uVar6 & 0xff00 | *(uint *)((long)psVar8 + (ulong)local_90) >> 0x18 |
                          (uVar6 & 0xff) << 0x10;
                }
                local_98 = psVar8;
                if (uVar6 != 0) {
                  uVar13 = 0;
                  uVar15 = 0;
                  do {
                    auVar16 = FUN_71028132dc(&local_98,uVar15);
                    psVar8 = auVar16._0_8_;
                    pcVar12 = pcVar1;
                    if ((auVar16._8_8_ & 0xff00000000) == 0xa000000000) {
                      sVar3 = *psVar8;
                      uVar2 = *(uint *)(psVar8 + 4);
                      uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                      uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                      if (sVar3 != 0x5942) {
                        uVar7 = uVar2;
                      }
                      if (uVar7 == 0) {
                        pcVar12 = "";
                      }
                      else {
                        pcVar12 = (char *)((long)psVar8 + (long)(int)uVar7);
                        if (*pcVar12 == -0x3b) {
                          uVar2 = *(uint *)(pcVar12 + 4);
                          uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                          uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                          if (sVar3 != 0x5942) {
                            uVar7 = uVar2;
                          }
                          lVar11 = *(long *)(pcVar12 + uVar7);
                        }
                        else {
                          lVar11 = 0;
                        }
                        uVar2 = *(uint *)(pcVar12 + ((long)(auVar16._8_8_ << 0x20) >> 0x1e) + 4);
                        uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                        uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                        if (sVar3 != 0x5942) {
                          uVar7 = uVar2;
                        }
                        pcVar12 = pcVar12 + (ulong)uVar7 + lVar11;
                      }
                    }
                    *(undefined1 *)((long)(int)param_3[0xb] + param_3[10] + -1) = 0;
                    if ((char *)param_3[10] == pcVar12) {
LAB_7101550164:
                      uVar7 = 3;
                    }
                    else {
                      ((char *)param_3[10])[(long)(int)param_3[0xb] + -1] = '\0';
                      pcVar10 = (char *)param_3[10];
                      uVar7 = 5;
                      if (*pcVar10 == *pcVar12) {
                        if (*pcVar10 != '\0') {
                          uVar5 = 0;
                          do {
                            uVar9 = uVar5;
                            if ((uVar9 == 0x400000) || (pcVar10[uVar9 + 1] != pcVar12[uVar9 + 1])) {
LAB_71015502bc:
                              uVar7 = 5;
                              goto LAB_7101550168;
                            }
                            if (pcVar10[uVar9 + 1] == '\0') goto LAB_71015502d0;
                            if (pcVar10[uVar9 + 2] != pcVar12[uVar9 + 2]) goto LAB_71015502bc;
                            if (pcVar10[uVar9 + 2] == '\0') {
                              uVar9 = uVar9 + 1;
                              goto LAB_71015502d0;
                            }
                            if (pcVar10[uVar9 + 3] != pcVar12[uVar9 + 3]) goto LAB_71015502bc;
                            if (pcVar10[uVar9 + 3] == '\0') {
                              uVar9 = uVar9 + 2;
                              goto LAB_71015502d0;
                            }
                            if (pcVar10[uVar9 + 4] != pcVar12[uVar9 + 4]) goto LAB_71015502bc;
                            uVar5 = uVar9 + 4;
                          } while (pcVar10[uVar9 + 4] != '\0');
                          uVar9 = uVar9 + 3;
LAB_71015502d0:
                          uVar7 = 5;
                          if (uVar9 >> 0x16 != 0) goto LAB_7101550168;
                        }
                        goto LAB_7101550164;
                      }
                    }
LAB_7101550168:
                    uVar15 = uVar15 + 1;
                    uVar13 = uVar7 | uVar13;
                  } while (uVar6 != uVar15);
                  if ((uVar13 & 3) == 1) goto LAB_710154fe40;
                }
              }
            }
            auVar16 = FUN_7102813520(&local_80,"ForkStrSub2Ary");
            local_98 = auVar16._0_8_;
            if ((local_98 == (short *)0x0) || ((auVar16._8_8_ & 0xf700000000) != 0xc000000000)) {
LAB_7101550524:
              param_1[1] = local_80;
              param_1[2] = CONCAT44(local_74,local_78);
              *param_1 = &DAT_710395e660;
              *(undefined1 *)(param_1 + 3) = 1;
              return;
            }
            uVar6 = auVar16._12_4_;
            local_8c = auVar16[0xc];
            local_90 = auVar16._8_4_;
            if (((uVar6 & 0xf7) != 0xc0) &&
               ((((uVar6 & 0xff) != 0xc1 && ((uVar6 & 0xff) != 0xc4)) && ((uVar6 & 0xe0) != 0x20))))
            goto LAB_7101550524;
            uVar6 = *(uint *)((long)local_98 + (ulong)local_90) >> 8;
            if (*local_98 == 0x5942) {
              uVar6 = uVar6 & 0xff00 | *(uint *)((long)local_98 + (ulong)local_90) >> 0x18 |
                      (uVar6 & 0xff) << 0x10;
            }
            if (uVar6 == 0) goto LAB_7101550524;
            uVar13 = 0;
            uVar15 = 0;
            do {
              auVar16 = FUN_71028132dc(&local_98,uVar15);
              psVar8 = auVar16._0_8_;
              pcVar12 = pcVar1;
              if ((auVar16._8_8_ & 0xff00000000) == 0xa000000000) {
                sVar3 = *psVar8;
                uVar2 = *(uint *)(psVar8 + 4);
                uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                if (sVar3 != 0x5942) {
                  uVar7 = uVar2;
                }
                if (uVar7 == 0) {
                  pcVar12 = "";
                }
                else {
                  pcVar12 = (char *)((long)psVar8 + (long)(int)uVar7);
                  if (*pcVar12 == -0x3b) {
                    uVar2 = *(uint *)(pcVar12 + 4);
                    uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                    uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                    if (sVar3 != 0x5942) {
                      uVar7 = uVar2;
                    }
                    lVar11 = *(long *)(pcVar12 + uVar7);
                  }
                  else {
                    lVar11 = 0;
                  }
                  uVar2 = *(uint *)(pcVar12 + ((long)(auVar16._8_8_ << 0x20) >> 0x1e) + 4);
                  uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                  uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                  if (sVar3 != 0x5942) {
                    uVar7 = uVar2;
                  }
                  pcVar12 = pcVar12 + (ulong)uVar7 + lVar11;
                }
              }
              *(undefined1 *)((long)(int)param_3[0x15] + param_3[0x14] + -1) = 0;
              if ((char *)param_3[0x14] == pcVar12) {
LAB_7101550394:
                uVar7 = 3;
              }
              else {
                ((char *)param_3[0x14])[(long)(int)param_3[0x15] + -1] = '\0';
                pcVar10 = (char *)param_3[0x14];
                uVar7 = 5;
                if (*pcVar10 == *pcVar12) {
                  if (*pcVar10 != '\0') {
                    uVar5 = 0;
                    do {
                      uVar9 = uVar5;
                      if ((uVar9 == 0x400000) || (pcVar10[uVar9 + 1] != pcVar12[uVar9 + 1])) {
LAB_71015504ec:
                        uVar7 = 5;
                        goto LAB_7101550398;
                      }
                      if (pcVar10[uVar9 + 1] == '\0') goto LAB_7101550500;
                      if (pcVar10[uVar9 + 2] != pcVar12[uVar9 + 2]) goto LAB_71015504ec;
                      if (pcVar10[uVar9 + 2] == '\0') {
                        uVar9 = uVar9 + 1;
                        goto LAB_7101550500;
                      }
                      if (pcVar10[uVar9 + 3] != pcVar12[uVar9 + 3]) goto LAB_71015504ec;
                      if (pcVar10[uVar9 + 3] == '\0') {
                        uVar9 = uVar9 + 2;
                        goto LAB_7101550500;
                      }
                      if (pcVar10[uVar9 + 4] != pcVar12[uVar9 + 4]) goto LAB_71015504ec;
                      uVar5 = uVar9 + 4;
                    } while (pcVar10[uVar9 + 4] != '\0');
                    uVar9 = uVar9 + 3;
LAB_7101550500:
                    uVar7 = 5;
                    if (uVar9 >> 0x16 != 0) goto LAB_7101550398;
                  }
                  goto LAB_7101550394;
                }
              }
LAB_7101550398:
              uVar15 = uVar15 + 1;
              uVar13 = uVar7 | uVar13;
            } while (uVar6 != uVar15);
            if ((uVar13 & 3) != 1) goto LAB_7101550524;
          }
          else {
            uVar6 = auVar16._12_4_;
            local_8c = auVar16[0xc];
            local_90 = auVar16._8_4_;
            local_98 = psVar8;
            if (((uVar6 & 0xf7) != 0xc0) &&
               ((((uVar6 & 0xff) != 0xc1 && ((uVar6 & 0xff) != 0xc4)) && ((uVar6 & 0xe0) != 0x20))))
            goto LAB_71015500c0;
            uVar6 = *(uint *)((long)psVar8 + (ulong)local_90) >> 8;
            if (*psVar8 == 0x5942) {
              uVar6 = uVar6 & 0xff00 | *(uint *)((long)psVar8 + (ulong)local_90) >> 0x18 |
                      (uVar6 & 0xff) << 0x10;
            }
            if (uVar6 == 0) goto LAB_71015500c0;
            uVar13 = 0;
            uVar15 = 0;
            do {
              auVar16 = FUN_71028132dc(&local_98,uVar15);
              psVar8 = auVar16._0_8_;
              pcVar12 = pcVar1;
              if ((auVar16._8_8_ & 0xff00000000) == 0xa000000000) {
                sVar3 = *psVar8;
                uVar2 = *(uint *)(psVar8 + 4);
                uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                if (sVar3 != 0x5942) {
                  uVar7 = uVar2;
                }
                if (uVar7 == 0) {
                  pcVar12 = "";
                }
                else {
                  pcVar12 = (char *)((long)psVar8 + (long)(int)uVar7);
                  if (*pcVar12 == -0x3b) {
                    uVar2 = *(uint *)(pcVar12 + 4);
                    uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                    uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                    if (sVar3 != 0x5942) {
                      uVar7 = uVar2;
                    }
                    lVar11 = *(long *)(pcVar12 + uVar7);
                  }
                  else {
                    lVar11 = 0;
                  }
                  uVar2 = *(uint *)(pcVar12 + ((long)(auVar16._8_8_ << 0x20) >> 0x1e) + 4);
                  uVar7 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
                  uVar7 = uVar7 >> 0x10 | uVar7 << 0x10;
                  if (sVar3 != 0x5942) {
                    uVar7 = uVar2;
                  }
                  pcVar12 = pcVar12 + (ulong)uVar7 + lVar11;
                }
              }
              *(undefined1 *)((long)(int)param_3[1] + *param_3 + -1) = 0;
              if ((char *)*param_3 == pcVar12) {
LAB_710154ff34:
                uVar7 = 3;
              }
              else {
                ((char *)*param_3)[(long)(int)param_3[1] + -1] = '\0';
                pcVar10 = (char *)*param_3;
                uVar7 = 5;
                if (*pcVar10 == *pcVar12) {
                  if (*pcVar10 != '\0') {
                    uVar5 = 0;
                    do {
                      uVar9 = uVar5;
                      if ((uVar9 == 0x400000) || (pcVar10[uVar9 + 1] != pcVar12[uVar9 + 1])) {
LAB_710155008c:
                        uVar7 = 5;
                        goto LAB_710154ff38;
                      }
                      if (pcVar10[uVar9 + 1] == '\0') goto LAB_71015500a0;
                      if (pcVar10[uVar9 + 2] != pcVar12[uVar9 + 2]) goto LAB_710155008c;
                      if (pcVar10[uVar9 + 2] == '\0') {
                        uVar9 = uVar9 + 1;
                        goto LAB_71015500a0;
                      }
                      if (pcVar10[uVar9 + 3] != pcVar12[uVar9 + 3]) goto LAB_710155008c;
                      if (pcVar10[uVar9 + 3] == '\0') {
                        uVar9 = uVar9 + 2;
                        goto LAB_71015500a0;
                      }
                      if (pcVar10[uVar9 + 4] != pcVar12[uVar9 + 4]) goto LAB_710155008c;
                      uVar5 = uVar9 + 4;
                    } while (pcVar10[uVar9 + 4] != '\0');
                    uVar9 = uVar9 + 3;
LAB_71015500a0:
                    uVar7 = 5;
                    if (uVar9 >> 0x16 != 0) goto LAB_710154ff38;
                  }
                  goto LAB_710154ff34;
                }
              }
LAB_710154ff38:
              uVar15 = uVar15 + 1;
              uVar13 = uVar7 | uVar13;
            } while (uVar6 != uVar15);
            if ((uVar13 & 3) != 1) goto LAB_71015500c0;
          }
LAB_710154fe40:
          uVar14 = uVar14 + 1;
        } while (uVar4 != uVar14);
      }
    }
  }
  *(undefined1 *)(param_1 + 3) = 0;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



char * FUN_71015505e0(long param_1,long param_2)

{
  byte *pbVar1;
  int iVar2;
  byte bVar3;
  short sVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  long lVar8;
  ulong uVar9;
  uint uVar10;
  int iVar11;
  short *psVar12;
  char *pcVar13;
  ulong uVar14;
  uint uVar15;
  char *pcVar16;
  uint uVar17;
  byte *pbVar18;
  uint uVar19;
  uint uVar20;
  undefined1 auVar21 [16];
  short *local_98;
  uint local_90;
  undefined1 local_8c;
  undefined *local_88;
  long local_80;
  undefined4 local_78;
  undefined1 local_74;
  undefined8 uStack_70;
  uint uStack_68;
  byte bStack_64;
  
  lVar8 = *(long *)(param_1 + 8);
  if (lVar8 == 0) {
    return "";
  }
  if ((*(byte *)(lVar8 + 0x16c) & 0xf7) == 0xc0) {
    uStack_68 = (uint)((ulong)*(undefined8 *)(lVar8 + 0x165) >> 0x18);
    bStack_64 = (byte)((ulong)*(undefined8 *)(lVar8 + 0x165) >> 0x38);
    psVar12 = *(short **)(lVar8 + 0x160);
    uStack_70._0_5_ = SUB85(psVar12,0);
    uStack_70._5_3_ = (undefined3)((ulong)psVar12 >> 0x28);
    if (((((bStack_64 & 0xf7) == 0xc0) || (bStack_64 == 0xc1)) || (bStack_64 == 0xc4)) ||
       ((bStack_64 & 0xe0) == 0x20)) {
      uVar5 = *(uint *)((long)psVar12 + (ulong)uStack_68) >> 8;
      if (*psVar12 == 0x5942) {
        uVar5 = uVar5 & 0xff00 | *(uint *)((long)psVar12 + (ulong)uStack_68) >> 0x18 |
                (uVar5 & 0xff) << 0x10;
      }
      if (uVar5 != 0) {
        uVar6 = 0;
        do {
          local_78 = 0;
          local_74 = 0;
          local_88 = &DAT_710395e680;
          local_80 = 0;
          auVar21 = FUN_71028132dc(&uStack_70,uVar6);
          if ((auVar21._0_8_ != 0) &&
             ((uVar7 = auVar21._12_4_ & 0xff, uVar7 == 0xc4 || (uVar7 == 0xc1)))) {
            local_78 = auVar21._8_4_;
            local_74 = auVar21[0xc];
            local_80 = auVar21._0_8_;
          }
          auVar21 = FUN_7102813520(&local_80,"ForkStrMainAry");
          psVar12 = auVar21._0_8_;
          if ((psVar12 == (short *)0x0) || ((auVar21._8_8_ & 0xf700000000) != 0xc000000000)) {
LAB_7101550950:
            auVar21 = FUN_7102813520(&local_80,"DemoStageRuntimeTypeAry");
            psVar12 = auVar21._0_8_;
            if ((psVar12 == (short *)0x0) || ((auVar21._8_8_ & 0xf700000000) != 0xc000000000)) {
LAB_7101550ccc:
              auVar21 = FUN_7102813520(&local_80,"StartBgmName");
              psVar12 = auVar21._0_8_;
              if ((auVar21._8_8_ & 0xff00000000) == 0xa000000000) {
                sVar4 = *psVar12;
                uVar6 = *(uint *)(psVar12 + 4);
                uVar5 = (uVar6 & 0xff00ff00) >> 8 | (uVar6 & 0xff00ff) << 8;
                uVar5 = uVar5 >> 0x10 | uVar5 << 0x10;
                if (sVar4 != 0x5942) {
                  uVar5 = uVar6;
                }
                if (uVar5 != 0) {
                  pcVar16 = (char *)((long)psVar12 + (long)(int)uVar5);
                  if (*pcVar16 == -0x3b) {
                    uVar6 = *(uint *)(pcVar16 + 4);
                    uVar5 = (uVar6 & 0xff00ff00) >> 8 | (uVar6 & 0xff00ff) << 8;
                    uVar5 = uVar5 >> 0x10 | uVar5 << 0x10;
                    if (sVar4 != 0x5942) {
                      uVar5 = uVar6;
                    }
                    lVar8 = *(long *)(pcVar16 + uVar5);
                  }
                  else {
                    lVar8 = 0;
                  }
                  uVar6 = *(uint *)(pcVar16 + ((long)(auVar21._8_8_ << 0x20) >> 0x1e) + 4);
                  uVar5 = (uVar6 & 0xff00ff00) >> 8 | (uVar6 & 0xff00ff) << 8;
                  uVar5 = uVar5 >> 0x10 | uVar5 << 0x10;
                  if (sVar4 != 0x5942) {
                    uVar5 = uVar6;
                  }
                  return pcVar16 + (ulong)uVar5 + lVar8;
                }
              }
              return "Ordinary_01";
            }
            uVar7 = auVar21._12_4_;
            local_8c = auVar21[0xc];
            local_90 = auVar21._8_4_;
            local_98 = psVar12;
            if (((uVar7 & 0xf7) != 0xc0) &&
               ((((uVar7 & 0xff) != 0xc1 && ((uVar7 & 0xff) != 0xc4)) && ((uVar7 & 0xe0) != 0x20))))
            goto LAB_7101550ccc;
            uVar7 = *(uint *)((long)psVar12 + (ulong)local_90) >> 8;
            if (*psVar12 == 0x5942) {
              uVar7 = uVar7 & 0xff00 | *(uint *)((long)psVar12 + (ulong)local_90) >> 0x18 |
                      (uVar7 & 0xff) << 0x10;
            }
            if (uVar7 == 0) goto LAB_7101550ccc;
            uVar20 = 0;
            uVar19 = 0;
            do {
              auVar21 = FUN_71028132dc(&local_98,uVar19);
              psVar12 = auVar21._0_8_;
              uVar10 = auVar21._12_4_ & 0xff;
              uVar15 = auVar21._8_4_;
              if (uVar10 == 0xd3) {
LAB_7101550a84:
                uVar14 = 0;
                iVar11 = 7;
                do {
                  uVar10 = (uint)uVar14;
                  uVar17 = iVar11 + uVar10 >> 1;
                  uVar14 = (ulong)uVar17;
                  if (*(uint *)(&DAT_71032af5f8 + (long)*(int *)(&DAT_71032af618 + uVar14 * 4) * 4)
                      == uVar15) goto LAB_7101550ae4;
                  iVar2 = uVar17 - 1;
                  if (uVar15 < *(uint *)(&DAT_71032af5f8 +
                                        (long)*(int *)(&DAT_71032af618 + uVar14 * 4) * 4)) {
                    uVar10 = uVar17 + 1;
                    iVar2 = iVar11;
                  }
                  iVar11 = iVar2;
                  uVar14 = (ulong)uVar10;
                } while ((int)uVar10 < iVar11);
                iVar11 = 0;
                if ((-1 < (int)uVar10) &&
                   (*(uint *)(&DAT_71032af5f8 +
                             (long)*(int *)(&DAT_71032af618 + (ulong)uVar10 * 4) * 4) == uVar15)) {
LAB_7101550ae4:
                  iVar11 = *(int *)(&DAT_71032af618 + uVar14 * 4);
joined_r0x007101550aec:
                  if (iVar11 < 0) goto LAB_71015509f4;
                }
              }
              else {
                if (uVar10 == 0xd1) {
                  if (-1 < (int)uVar15) goto LAB_7101550a84;
                }
                else if (uVar10 == 0xa0) {
                  sVar4 = *psVar12;
                  uVar15 = *(uint *)(psVar12 + 4);
                  uVar10 = (uVar15 & 0xff00ff00) >> 8 | (uVar15 & 0xff00ff) << 8;
                  uVar10 = uVar10 >> 0x10 | uVar10 << 0x10;
                  if (sVar4 != 0x5942) {
                    uVar10 = uVar15;
                  }
                  if (uVar10 != 0) {
                    pcVar16 = (char *)((long)psVar12 + (long)(int)uVar10);
                    if (*pcVar16 == -0x3b) {
                      uVar15 = *(uint *)(pcVar16 + 4);
                      uVar10 = (uVar15 & 0xff00ff00) >> 8 | (uVar15 & 0xff00ff) << 8;
                      uVar10 = uVar10 >> 0x10 | uVar10 << 0x10;
                      if (sVar4 != 0x5942) {
                        uVar10 = uVar15;
                      }
                      lVar8 = *(long *)(pcVar16 + uVar10);
                    }
                    else {
                      lVar8 = 0;
                    }
                    uVar15 = *(uint *)(pcVar16 + ((auVar21._8_8_ << 0x20) >> 0x1e) + 4);
                    uVar10 = (uVar15 & 0xff00ff00) >> 8 | (uVar15 & 0xff00ff) << 8;
                    uVar10 = uVar10 >> 0x10 | uVar10 << 0x10;
                    if (sVar4 != 0x5942) {
                      uVar10 = uVar15;
                    }
                    pbVar1 = (byte *)(pcVar16 + (ulong)uVar10 + lVar8);
                    bVar3 = *pbVar1;
                    if (bVar3 == 0) {
                      uVar15 = 0;
                      uVar10 = 0;
                    }
                    else {
                      uVar14 = 0;
                      uVar15 = 0;
                      pbVar18 = pbVar1;
                      do {
                        uVar17 = (uint)bVar3;
                        iVar11 = (int)uVar14;
                        uVar10 = iVar11 + 1;
                        if (pbVar1[uVar10] == 0) {
                          uVar17 = uVar17 * 0x16a88000 | uVar17 * -0x3361d2af >> 0x11;
LAB_7101550be0:
                          uVar15 = uVar17 * 0x1b873593 ^ uVar15;
                          break;
                        }
                        uVar10 = iVar11 + 2;
                        if (pbVar1[uVar10] == 0) {
                          uVar17 = (uint)CONCAT11(pbVar18[1],bVar3);
LAB_7101550bd4:
                          uVar17 = uVar17 * 0x16a88000 | uVar17 * -0x3361d2af >> 0x11;
                          goto LAB_7101550be0;
                        }
                        uVar10 = iVar11 + 3;
                        if (pbVar1[uVar10] == 0) {
                          uVar17 = uVar17 | (uint)pbVar18[2] << 0x10 | (uint)pbVar18[1] << 8;
                          goto LAB_7101550bd4;
                        }
                        iVar2 = *(int *)pbVar18;
                        uVar10 = iVar11 + 4;
                        uVar14 = (ulong)uVar10;
                        pbVar18 = pbVar1 + uVar14;
                        uVar15 = (iVar2 * 0x16a88000 | (uint)(iVar2 * -0x3361d2af) >> 0x11) *
                                 0x1b873593 ^ uVar15;
                        bVar3 = *pbVar18;
                        uVar15 = (uVar15 >> 0x13 | uVar15 << 0xd) * 5 + 0xe6546b64;
                      } while (bVar3 != 0);
                    }
                    uVar14 = 0;
                    uVar10 = (uVar10 ^ uVar15 ^ (uVar10 ^ uVar15) >> 0x10) * -0x7a143595;
                    uVar10 = (uVar10 ^ uVar10 >> 0xd) * -0x3d4d51cb;
                    uVar10 = uVar10 ^ uVar10 >> 0x10;
                    iVar11 = 7;
                    do {
                      uVar15 = (uint)uVar14;
                      uVar17 = iVar11 + uVar15 >> 1;
                      uVar14 = (ulong)uVar17;
                      if (*(uint *)(&DAT_71032af5f8 +
                                   (long)*(int *)(&DAT_71032af618 + uVar14 * 4) * 4) == uVar10)
                      goto LAB_7101550c74;
                      iVar2 = uVar17 - 1;
                      if (uVar10 < *(uint *)(&DAT_71032af5f8 +
                                            (long)*(int *)(&DAT_71032af618 + uVar14 * 4) * 4)) {
                        uVar15 = uVar17 + 1;
                        iVar2 = iVar11;
                      }
                      iVar11 = iVar2;
                      uVar14 = (ulong)uVar15;
                    } while ((int)uVar15 < iVar11);
                    iVar11 = 0;
                    if ((-1 < (int)uVar15) &&
                       (iVar11 = 0,
                       *(uint *)(&DAT_71032af5f8 +
                                (long)*(int *)(&DAT_71032af618 + (ulong)uVar15 * 4) * 4) == uVar10))
                    {
LAB_7101550c74:
                      iVar11 = *(int *)(&DAT_71032af618 + uVar14 * 4);
                      goto joined_r0x007101550aec;
                    }
                    goto LAB_71015509f8;
                  }
                }
LAB_71015509f4:
                iVar11 = 0;
              }
LAB_71015509f8:
              uVar19 = uVar19 + 1;
              uVar10 = 3;
              if (*(int *)(param_2 + 0xe0) != iVar11) {
                uVar10 = 5;
              }
              uVar20 = uVar10 | uVar20;
            } while (uVar7 != uVar19);
            if ((uVar20 & 3) != 1) goto LAB_7101550ccc;
          }
          else {
            uVar7 = auVar21._12_4_;
            local_8c = auVar21[0xc];
            local_90 = auVar21._8_4_;
            local_98 = psVar12;
            if (((uVar7 & 0xf7) != 0xc0) &&
               ((((uVar7 & 0xff) != 0xc1 && ((uVar7 & 0xff) != 0xc4)) && ((uVar7 & 0xe0) != 0x20))))
            goto LAB_7101550950;
            uVar7 = *(uint *)((long)psVar12 + (ulong)local_90) >> 8;
            if (*psVar12 == 0x5942) {
              uVar7 = uVar7 & 0xff00 | *(uint *)((long)psVar12 + (ulong)local_90) >> 0x18 |
                      (uVar7 & 0xff) << 0x10;
            }
            if (uVar7 == 0) goto LAB_7101550950;
            uVar20 = 0;
            uVar19 = 0;
            do {
              auVar21 = FUN_71028132dc(&local_98,uVar19);
              psVar12 = auVar21._0_8_;
              pcVar16 = "";
              if ((auVar21._8_8_ & 0xff00000000) == 0xa000000000) {
                sVar4 = *psVar12;
                uVar15 = *(uint *)(psVar12 + 4);
                uVar10 = (uVar15 & 0xff00ff00) >> 8 | (uVar15 & 0xff00ff) << 8;
                uVar10 = uVar10 >> 0x10 | uVar10 << 0x10;
                if (sVar4 != 0x5942) {
                  uVar10 = uVar15;
                }
                if (uVar10 == 0) {
                  pcVar16 = "";
                }
                else {
                  pcVar16 = (char *)((long)psVar12 + (long)(int)uVar10);
                  if (*pcVar16 == -0x3b) {
                    uVar15 = *(uint *)(pcVar16 + 4);
                    uVar10 = (uVar15 & 0xff00ff00) >> 8 | (uVar15 & 0xff00ff) << 8;
                    uVar10 = uVar10 >> 0x10 | uVar10 << 0x10;
                    if (sVar4 != 0x5942) {
                      uVar10 = uVar15;
                    }
                    lVar8 = *(long *)(pcVar16 + uVar10);
                  }
                  else {
                    lVar8 = 0;
                  }
                  uVar15 = *(uint *)(pcVar16 + ((long)(auVar21._8_8_ << 0x20) >> 0x1e) + 4);
                  uVar10 = (uVar15 & 0xff00ff00) >> 8 | (uVar15 & 0xff00ff) << 8;
                  uVar10 = uVar10 >> 0x10 | uVar10 << 0x10;
                  if (sVar4 != 0x5942) {
                    uVar10 = uVar15;
                  }
                  pcVar16 = pcVar16 + (ulong)uVar10 + lVar8;
                }
              }
              *(undefined1 *)((long)*(int *)(param_2 + 0x338) + *(long *)(param_2 + 0x330) + -1) = 0
              ;
              if (*(char **)(param_2 + 0x330) == pcVar16) {
LAB_71015507b0:
                uVar10 = 3;
              }
              else {
                (*(char **)(param_2 + 0x330))[(long)*(int *)(param_2 + 0x338) + -1] = '\0';
                pcVar13 = *(char **)(param_2 + 0x330);
                uVar10 = 5;
                if (*pcVar13 == *pcVar16) {
                  if (*pcVar13 != '\0') {
                    uVar14 = 0;
                    do {
                      uVar9 = uVar14;
                      if ((uVar9 == 0x400000) || (pcVar13[uVar9 + 1] != pcVar16[uVar9 + 1])) {
LAB_7101550914:
                        uVar10 = 5;
                        goto LAB_71015507b4;
                      }
                      if (pcVar13[uVar9 + 1] == '\0') goto LAB_7101550928;
                      if (pcVar13[uVar9 + 2] != pcVar16[uVar9 + 2]) goto LAB_7101550914;
                      if (pcVar13[uVar9 + 2] == '\0') {
                        uVar9 = uVar9 + 1;
                        goto LAB_7101550928;
                      }
                      if (pcVar13[uVar9 + 3] != pcVar16[uVar9 + 3]) goto LAB_7101550914;
                      if (pcVar13[uVar9 + 3] == '\0') {
                        uVar9 = uVar9 + 2;
                        goto LAB_7101550928;
                      }
                      if (pcVar13[uVar9 + 4] != pcVar16[uVar9 + 4]) goto LAB_7101550914;
                      uVar14 = uVar9 + 4;
                    } while (pcVar13[uVar9 + 4] != '\0');
                    uVar9 = uVar9 + 3;
LAB_7101550928:
                    uVar10 = 5;
                    if (uVar9 >> 0x16 != 0) goto LAB_71015507b4;
                  }
                  goto LAB_71015507b0;
                }
              }
LAB_71015507b4:
              uVar19 = uVar19 + 1;
              uVar20 = uVar10 | uVar20;
            } while (uVar7 != uVar19);
            if ((uVar20 & 3) != 1) goto LAB_7101550950;
          }
          uVar6 = uVar6 + 1;
        } while (uVar5 != uVar6);
        lVar8 = *(long *)(param_1 + 8);
      }
    }
  }
  return *(char **)(lVar8 + 0x158);
}



undefined4 FUN_7101550d70(long param_1,long param_2)

{
  uint uVar1;
  short sVar2;
  uint uVar3;
  ulong uVar4;
  uint uVar5;
  uint uVar6;
  long lVar7;
  ulong uVar8;
  short *psVar9;
  char *pcVar10;
  char *pcVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  undefined1 auVar15 [16];
  long local_a8;
  undefined4 local_a0;
  undefined1 local_9c;
  undefined8 uStack_98;
  uint uStack_90;
  byte bStack_8c;
  undefined1 local_88 [16];
  short *local_78;
  undefined8 local_70;
  undefined4 local_64;
  
  lVar7 = *(long *)(param_1 + 8);
  if (lVar7 == 0) {
    return 0;
  }
  if ((*(byte *)(lVar7 + 0x7c) & 0xf7) == 0xc0) {
    uStack_90 = (uint)((ulong)*(undefined8 *)(lVar7 + 0x75) >> 0x18);
    bStack_8c = (byte)((ulong)*(undefined8 *)(lVar7 + 0x75) >> 0x38);
    psVar9 = *(short **)(lVar7 + 0x70);
    uStack_98._0_5_ = SUB85(psVar9,0);
    uStack_98._5_3_ = (undefined3)((ulong)psVar9 >> 0x28);
    if (((((bStack_8c & 0xf7) == 0xc0) || (bStack_8c == 0xc1)) || (bStack_8c == 0xc4)) ||
       ((bStack_8c & 0xe0) == 0x20)) {
      uVar3 = *(uint *)((long)psVar9 + (ulong)uStack_90) >> 8;
      if (*psVar9 == 0x5942) {
        uVar3 = uVar3 & 0xff00 | *(uint *)((long)psVar9 + (ulong)uStack_90) >> 0x18 |
                (uVar3 & 0xff) << 0x10;
      }
      if (uVar3 != 0) {
        uVar13 = 0;
        do {
          local_a0 = 0;
          local_9c = 0;
          local_a8 = 0;
          auVar15 = FUN_71028132dc(&uStack_98,uVar13);
          if ((auVar15._0_8_ != 0) &&
             ((uVar5 = auVar15._12_4_ & 0xff, uVar5 == 0xc4 || (uVar5 == 0xc1)))) {
            local_a0 = auVar15._8_4_;
            local_9c = auVar15[0xc];
            local_a8 = auVar15._0_8_;
          }
          auVar15 = FUN_7102813520(&local_a8,"ForkStrMainAry");
          local_78 = auVar15._0_8_;
          if ((local_78 == (short *)0x0) || ((auVar15._8_8_ & 0xf700000000) != 0xc000000000)) {
LAB_71015510c8:
            local_70 = &local_64;
            local_64 = 0;
            local_78 = (short *)&DAT_710395e390;
            local_88 = FUN_7102813520(&local_a8,"DemoFaderType");
            uVar4 = FUN_7101552270((long)&local_78,(undefined8 *)local_88);
            if ((uVar4 & 1) != 0) {
              return local_64;
            }
            return 0;
          }
          uVar5 = auVar15._12_4_;
          local_70 = (undefined4 *)CONCAT44(CONCAT31(local_70._5_3_,auVar15[0xc]),auVar15._8_4_);
          if (((uVar5 & 0xf7) != 0xc0) &&
             ((((uVar5 & 0xff) != 0xc1 && ((uVar5 & 0xff) != 0xc4)) && ((uVar5 & 0xe0) != 0x20))))
          goto LAB_71015510c8;
          uVar14 = *(uint *)((long)local_78 + (ulong)auVar15._8_4_);
          uVar5 = uVar14 >> 8;
          if (*local_78 == 0x5942) {
            uVar5 = uVar5 & 0xff00 | uVar14 >> 0x18 | (uVar5 & 0xff) << 0x10;
          }
          if (uVar5 == 0) goto LAB_71015510c8;
          uVar12 = 0;
          uVar14 = 0;
          do {
            auVar15 = FUN_71028132dc(&local_78,uVar14);
            psVar9 = auVar15._0_8_;
            pcVar11 = "";
            if ((auVar15._8_8_ & 0xff00000000) == 0xa000000000) {
              sVar2 = *psVar9;
              uVar1 = *(uint *)(psVar9 + 4);
              uVar6 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
              uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
              if (sVar2 != 0x5942) {
                uVar6 = uVar1;
              }
              if (uVar6 == 0) {
                pcVar11 = "";
              }
              else {
                pcVar11 = (char *)((long)psVar9 + (long)(int)uVar6);
                if (*pcVar11 == -0x3b) {
                  uVar1 = *(uint *)(pcVar11 + 4);
                  uVar6 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                  uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
                  if (sVar2 != 0x5942) {
                    uVar6 = uVar1;
                  }
                  lVar7 = *(long *)(pcVar11 + uVar6);
                }
                else {
                  lVar7 = 0;
                }
                uVar1 = *(uint *)(pcVar11 + ((long)(auVar15._8_8_ << 0x20) >> 0x1e) + 4);
                uVar6 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
                if (sVar2 != 0x5942) {
                  uVar6 = uVar1;
                }
                pcVar11 = pcVar11 + (ulong)uVar6 + lVar7;
              }
            }
            *(undefined1 *)((long)*(int *)(param_2 + 0x338) + *(long *)(param_2 + 0x330) + -1) = 0;
            if (*(char **)(param_2 + 0x330) == pcVar11) {
LAB_7101550f24:
              uVar6 = 3;
            }
            else {
              (*(char **)(param_2 + 0x330))[(long)*(int *)(param_2 + 0x338) + -1] = '\0';
              pcVar10 = *(char **)(param_2 + 0x330);
              uVar6 = 5;
              if (*pcVar10 == *pcVar11) {
                if (*pcVar10 != '\0') {
                  uVar4 = 0;
                  do {
                    uVar8 = uVar4;
                    if ((uVar8 == 0x400000) || (pcVar10[uVar8 + 1] != pcVar11[uVar8 + 1])) {
LAB_710155107c:
                      uVar6 = 5;
                      goto LAB_7101550f28;
                    }
                    if (pcVar10[uVar8 + 1] == '\0') goto LAB_7101551090;
                    if (pcVar10[uVar8 + 2] != pcVar11[uVar8 + 2]) goto LAB_710155107c;
                    if (pcVar10[uVar8 + 2] == '\0') {
                      uVar8 = uVar8 + 1;
                      goto LAB_7101551090;
                    }
                    if (pcVar10[uVar8 + 3] != pcVar11[uVar8 + 3]) goto LAB_710155107c;
                    if (pcVar10[uVar8 + 3] == '\0') {
                      uVar8 = uVar8 + 2;
                      goto LAB_7101551090;
                    }
                    if (pcVar10[uVar8 + 4] != pcVar11[uVar8 + 4]) goto LAB_710155107c;
                    uVar4 = uVar8 + 4;
                  } while (pcVar10[uVar8 + 4] != '\0');
                  uVar8 = uVar8 + 3;
LAB_7101551090:
                  uVar6 = 5;
                  if (uVar8 >> 0x16 != 0) goto LAB_7101550f28;
                }
                goto LAB_7101550f24;
              }
            }
LAB_7101550f28:
            uVar14 = uVar14 + 1;
            uVar12 = uVar6 | uVar12;
          } while (uVar5 != uVar14);
          if ((uVar12 & 3) != 1) goto LAB_71015510c8;
          uVar13 = uVar13 + 1;
        } while (uVar3 != uVar13);
        lVar7 = *(long *)(param_1 + 8);
      }
    }
  }
  return *(undefined4 *)(lVar7 + 0x19c);
}



undefined8 FUN_7101551130(long param_1,long *param_2)

{
  uint uVar1;
  undefined1 auVar2 [12];
  uint uVar3;
  ulong uVar4;
  long lVar5;
  short *psVar6;
  uint uVar7;
  undefined1 auVar8 [16];
  long local_58;
  undefined8 uStack_50;
  undefined4 local_48;
  undefined1 local_44;
  undefined8 uStack_40;
  uint uStack_38;
  byte bStack_34;
  
  lVar5 = *(long *)(param_1 + 8);
  if (lVar5 == 0) {
    return 0;
  }
  if ((*(byte *)(lVar5 + 0xbc) & 0xf7) == 0xc0) {
    uStack_38 = (uint)((ulong)*(undefined8 *)(lVar5 + 0xb5) >> 0x18);
    bStack_34 = (byte)((ulong)*(undefined8 *)(lVar5 + 0xb5) >> 0x38);
    psVar6 = *(short **)(lVar5 + 0xb0);
    uStack_40._0_5_ = SUB85(psVar6,0);
    uStack_40._5_3_ = (undefined3)((ulong)psVar6 >> 0x28);
    if (((((bStack_34 & 0xf7) == 0xc0) || (bStack_34 == 0xc1)) || (bStack_34 == 0xc4)) ||
       ((bStack_34 & 0xe0) == 0x20)) {
      uVar1 = *(uint *)((long)psVar6 + (ulong)uStack_38) >> 8;
      if (*psVar6 == 0x5942) {
        uVar1 = uVar1 & 0xff00 | *(uint *)((long)psVar6 + (ulong)uStack_38) >> 0x18 |
                (uVar1 & 0xff) << 0x10;
      }
      if (uVar1 != 0) {
        uVar7 = 0;
        lVar5 = DAT_7103a5a510 + 0x10;
        do {
          auVar8 = FUN_71028132dc(&uStack_40,uVar7);
          auVar2 = auVar8._0_12_;
          if (auVar8._0_8_ == 0) {
            local_44 = 0;
            auVar2 = ZEXT812(0);
          }
          else {
            local_44 = auVar8[0xc];
            uVar3 = auVar8._12_4_ & 0xff;
            if ((uVar3 != 0xc4) && (uVar3 != 0xc1)) {
              local_44 = 0;
              auVar2 = SUB1612(ZEXT816(0),0) << 0x40;
            }
          }
          uStack_50 = auVar2._0_8_;
          local_48 = auVar2._8_4_;
          local_58 = lVar5;
          uVar4 = FUN_71019f3920((long)&local_58,param_2);
          if ((uVar4 & 1) != 0) {
            return 1;
          }
          uVar7 = uVar7 + 1;
        } while (uVar1 != uVar7);
      }
    }
  }
  return 0;
}



int FUN_710155127c(long param_1)

{
  bool bVar1;
  ulong uVar2;
  long lVar3;
  undefined8 uVar4;
  undefined8 local_58;
  undefined4 local_50;
  undefined1 local_4c;
  undefined1 local_48 [16];
  undefined *local_38;
  int *piStack_30;
  int local_24;
  
  lVar3 = *(long *)(param_1 + 8);
  if (lVar3 == 0) {
    return 0;
  }
  local_50 = 0;
  local_4c = 0;
  local_58._0_5_ = 0;
  local_58._5_3_ = 0;
  if ((*(char *)(lVar3 + 0xf4) == -0x3c) || (*(char *)(lVar3 + 0xf4) == -0x3f)) {
    local_58._0_5_ = (undefined5)*(undefined8 *)(lVar3 + 0xe8);
    uVar4 = *(undefined8 *)(lVar3 + 0xed);
    local_58._5_3_ = (undefined3)uVar4;
    local_50 = (undefined4)((ulong)uVar4 >> 0x18);
    local_4c = (undefined1)((ulong)uVar4 >> 0x38);
  }
  local_24 = 0;
  piStack_30 = &local_24;
  local_38 = &DAT_710395e440;
  local_48 = FUN_7102813520(&local_58,"DemoStageCategory");
  uVar2 = FUN_71015527d0((long)&local_38,(undefined8 *)local_48);
  if ((uVar2 & 1) == 0) {
    local_24 = 0;
  }
  if ((local_24 == 6) || (bVar1 = local_24 == 3, local_24 = 0, bVar1)) {
    lVar3 = *(long *)(param_1 + 8);
    local_50 = 0;
    local_4c = 0;
    local_58._0_5_ = 0;
    local_58._5_3_ = 0;
    if ((*(char *)(lVar3 + 0xf4) == -0x3c) || (*(char *)(lVar3 + 0xf4) == -0x3f)) {
      local_58._0_5_ = (undefined5)*(undefined8 *)(lVar3 + 0xe8);
      uVar4 = *(undefined8 *)(lVar3 + 0xed);
      local_58._5_3_ = (undefined3)uVar4;
      local_50 = (undefined4)((ulong)uVar4 >> 0x18);
      local_4c = (undefined1)((ulong)uVar4 >> 0x38);
    }
    local_24 = 0;
    piStack_30 = &local_24;
    local_38 = (undefined *)(DAT_7103a5b0a0 + 0x10);
    local_48 = FUN_7102813520(&local_58,"DemoStageMapObjectType");
    uVar2 = FUN_7100c2a980((long)&local_38,(undefined8 *)local_48);
    if ((uVar2 & 1) == 0) {
      local_24 = 0;
    }
  }
  return local_24;
}



ulong FUN_71015513c0(long param_1)

{
  short sVar1;
  long lVar2;
  uint uVar3;
  short *psVar4;
  ulong uVar5;
  long lVar6;
  undefined8 uVar7;
  char *pcVar8;
  uint uVar9;
  char *pcVar10;
  undefined1 auVar11 [16];
  undefined8 local_20;
  undefined4 local_18;
  undefined1 local_14;
  
  lVar6 = *(long *)(param_1 + 8);
  if (lVar6 == 0) {
    return 0;
  }
  local_18 = 0;
  local_14 = 0;
  local_20._0_5_ = 0;
  local_20._5_3_ = 0;
  if ((*(char *)(lVar6 + 0xf4) == -0x3c) || (*(char *)(lVar6 + 0xf4) == -0x3f)) {
    local_20._0_5_ = (undefined5)*(undefined8 *)(lVar6 + 0xe8);
    uVar7 = *(undefined8 *)(lVar6 + 0xed);
    local_20._5_3_ = (undefined3)uVar7;
    local_18 = (undefined4)((ulong)uVar7 >> 0x18);
    local_14 = (undefined1)((ulong)uVar7 >> 0x38);
  }
  auVar11 = FUN_7102813520(&local_20,"DemoStageAreaType");
  psVar4 = auVar11._0_8_;
  if ((auVar11._8_8_ & 0xff00000000) == 0xa000000000) {
    sVar1 = *psVar4;
    uVar9 = *(uint *)(psVar4 + 4);
    uVar3 = (uVar9 & 0xff00ff00) >> 8 | (uVar9 & 0xff00ff) << 8;
    uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
    if (sVar1 != 0x5942) {
      uVar3 = uVar9;
    }
    if (uVar3 != 0) {
      pcVar8 = (char *)((long)psVar4 + (long)(int)uVar3);
      if (*pcVar8 == -0x3b) {
        uVar9 = *(uint *)(pcVar8 + 4);
        uVar3 = (uVar9 & 0xff00ff00) >> 8 | (uVar9 & 0xff00ff) << 8;
        uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
        if (sVar1 != 0x5942) {
          uVar3 = uVar9;
        }
        lVar6 = *(long *)(pcVar8 + uVar3);
      }
      else {
        lVar6 = 0;
      }
      uVar9 = *(uint *)(pcVar8 + ((long)(auVar11._8_8_ << 0x20) >> 0x1e) + 4);
      uVar3 = (uVar9 & 0xff00ff00) >> 8 | (uVar9 & 0xff00ff) << 8;
      uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
      if (sVar1 != 0x5942) {
        uVar3 = uVar9;
      }
      pcVar8 = pcVar8 + (ulong)uVar3 + lVar6;
      goto LAB_71015514a4;
    }
  }
  pcVar8 = "Invalid";
LAB_71015514a4:
  uVar5 = 0;
  do {
    uVar3 = (uint)uVar5;
    pcVar10 = "";
    if (uVar3 < 0x54) {
      pcVar10 = *(char **)(DAT_7103a5b098 + uVar5 * 8 + 0x600);
    }
    if (pcVar8 == pcVar10) {
      return uVar5;
    }
    if (*pcVar8 == *pcVar10) {
      if (*pcVar8 == '\0') {
        return uVar5;
      }
      lVar6 = 0;
      while ((lVar6 != 0x400000 && (pcVar8[lVar6 + 1] == pcVar10[lVar6 + 1]))) {
        if (pcVar8[lVar6 + 1] == '\0') {
          return uVar5;
        }
        if (pcVar8[lVar6 + 2] != pcVar10[lVar6 + 2]) break;
        if (pcVar8[lVar6 + 2] == '\0') {
          return uVar5;
        }
        if (pcVar8[lVar6 + 3] != pcVar10[lVar6 + 3]) break;
        if (pcVar8[lVar6 + 3] == '\0') {
          return uVar5;
        }
        lVar2 = lVar6 + 4;
        if (pcVar8[lVar2] != pcVar10[lVar6 + 4]) break;
        lVar6 = lVar6 + 4;
        if (pcVar8[lVar2] == '\0') {
          return uVar5;
        }
      }
    }
    uVar9 = 0x54;
    if ((int)uVar3 < 0x54) {
      uVar9 = uVar3 + 1;
    }
    uVar5 = (ulong)uVar9;
    if (uVar9 == 0x54) {
      return 0;
    }
  } while( true );
}



undefined8 FUN_710155158c(long param_1)

{
  uint uVar1;
  int iVar2;
  ulong uVar3;
  long lVar4;
  undefined8 uVar5;
  undefined1 auVar6 [16];
  undefined8 local_58;
  undefined4 local_50;
  undefined1 local_4c;
  undefined1 local_48 [16];
  undefined *local_38;
  int *piStack_30;
  int local_24;
  
  if (((DAT_710407a408 & 1) == 0) && (iVar2 = thunk_EXT_FUN_02e95df0(&DAT_710407a408), iVar2 != 0))
  {
    thunk_EXT_FUN_02e95df0(&DAT_710407a408);
  }
  lVar4 = *(long *)(param_1 + 8);
  if (lVar4 != 0) {
    local_50 = 0;
    local_4c = 0;
    local_58._0_5_ = 0;
    local_58._5_3_ = 0;
    if ((*(char *)(lVar4 + 0xf4) == -0x3c) || (*(char *)(lVar4 + 0xf4) == -0x3f)) {
      local_58._0_5_ = (undefined5)*(undefined8 *)(lVar4 + 0xe8);
      uVar5 = *(undefined8 *)(lVar4 + 0xed);
      local_58._5_3_ = (undefined3)uVar5;
      local_50 = (undefined4)((ulong)uVar5 >> 0x18);
      local_4c = (undefined1)((ulong)uVar5 >> 0x38);
    }
    local_24 = 0;
    piStack_30 = &local_24;
    local_38 = &DAT_710395e440;
    local_48 = FUN_7102813520(&local_58,"DemoStageCategory");
    uVar3 = FUN_71015527d0((long)&local_38,(undefined8 *)local_48);
    if ((uVar3 & 1) == 0) {
      return 0;
    }
    if (1 < local_24 - 5U) {
      return 0;
    }
    lVar4 = *(long *)(param_1 + 8);
    local_50 = 0;
    local_4c = 0;
    local_58._0_5_ = 0;
    local_58._5_3_ = 0;
    if ((*(char *)(lVar4 + 0xf4) == -0x3c) || (*(char *)(lVar4 + 0xf4) == -0x3f)) {
      local_58._0_5_ = (undefined5)*(undefined8 *)(lVar4 + 0xe8);
      uVar5 = *(undefined8 *)(lVar4 + 0xed);
      local_58._5_3_ = (undefined3)uVar5;
      local_50 = (undefined4)((ulong)uVar5 >> 0x18);
      local_4c = (undefined1)((ulong)uVar5 >> 0x38);
    }
    auVar6 = FUN_7102813520(&local_58,"DemoStageMapFileParamId");
    uVar1 = auVar6._12_4_ & 0xff;
    if (uVar1 == 0xd3) {
      return auVar6._8_8_;
    }
    if ((uVar1 == 0xd1) && (-1 < auVar6._8_4_)) {
      return auVar6._8_8_;
    }
  }
  return 0;
}



int FUN_71015517f4(long param_1)

{
  int iVar1;
  ulong uVar2;
  long lVar3;
  undefined8 uVar4;
  undefined8 local_58;
  undefined4 local_50;
  undefined1 local_4c;
  undefined1 local_48 [16];
  undefined *local_38;
  int *piStack_30;
  int local_24;
  
  lVar3 = *(long *)(param_1 + 8);
  if (lVar3 == 0) {
    return 0;
  }
  local_50 = 0;
  local_4c = 0;
  local_58._0_5_ = 0;
  local_58._5_3_ = 0;
  if ((*(char *)(lVar3 + 0xf4) == -0x3c) || (*(char *)(lVar3 + 0xf4) == -0x3f)) {
    local_58._0_5_ = (undefined5)*(undefined8 *)(lVar3 + 0xe8);
    uVar4 = *(undefined8 *)(lVar3 + 0xed);
    local_58._5_3_ = (undefined3)uVar4;
    local_50 = (undefined4)((ulong)uVar4 >> 0x18);
    local_4c = (undefined1)((ulong)uVar4 >> 0x38);
  }
  local_24 = 0;
  piStack_30 = &local_24;
  local_38 = &DAT_710395e440;
  local_48 = FUN_7102813520(&local_58,"DemoStageCategory");
  uVar2 = FUN_71015527d0((long)&local_38,(undefined8 *)local_48);
  iVar1 = 0;
  if (((uVar2 & 1) != 0) && (local_24 == 5)) {
    lVar3 = *(long *)(param_1 + 8);
    local_50 = 0;
    local_4c = 0;
    local_58._0_5_ = 0;
    local_58._5_3_ = 0;
    if ((*(char *)(lVar3 + 0xf4) == -0x3c) || (*(char *)(lVar3 + 0xf4) == -0x3f)) {
      local_58._0_5_ = (undefined5)*(undefined8 *)(lVar3 + 0xe8);
      uVar4 = *(undefined8 *)(lVar3 + 0xed);
      local_58._5_3_ = (undefined3)uVar4;
      local_50 = (undefined4)((ulong)uVar4 >> 0x18);
      local_4c = (undefined1)((ulong)uVar4 >> 0x38);
    }
    local_24 = 0;
    piStack_30 = &local_24;
    local_38 = &DAT_710395e570;
    local_48 = FUN_7102813520(&local_58,"DemoStageOriginalMapAxisType");
    uVar2 = FUN_7101552d68((long)&local_38,(undefined8 *)local_48);
    iVar1 = local_24;
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
  }
  return iVar1;
}



void FUN_7101551930(long *param_1,long param_2,uint param_3)

{
  uint uVar1;
  short sVar2;
  uint uVar3;
  long lVar4;
  short *psVar5;
  char *pcVar6;
  long lVar7;
  undefined1 auVar8 [16];
  undefined8 local_30;
  undefined5 uStack_28;
  
  lVar7 = *(long *)(param_2 + 8);
  if (((lVar7 == 0) || ((int)param_3 < 0)) || ((*(byte *)(lVar7 + 0x8c) & 0xf7) != 0xc0)) {
LAB_71015519fc:
    FUN_7100cb0550(param_1,DAT_7103a5c780);
    return;
  }
  uVar1 = *(uint *)((long)*(short **)(lVar7 + 0x80) + (ulong)*(uint *)(lVar7 + 0x88));
  uVar3 = uVar1 >> 8;
  if (**(short **)(lVar7 + 0x80) == 0x5942) {
    uVar3 = uVar3 & 0xff00 | uVar1 >> 0x18 | (uVar3 & 0xff) << 0x10;
  }
  if (uVar3 <= param_3) goto LAB_71015519fc;
  local_30._0_5_ = (undefined5)*(undefined8 *)(lVar7 + 0x80);
  local_30._5_3_ = (undefined3)*(undefined8 *)(lVar7 + 0x85);
  uStack_28 = (undefined5)((ulong)*(undefined8 *)(lVar7 + 0x85) >> 0x18);
  auVar8 = FUN_71028132dc(&local_30,param_3);
  psVar5 = auVar8._0_8_;
  if ((auVar8._8_8_ & 0xff00000000) == 0xa000000000) {
    sVar2 = *psVar5;
    uVar1 = *(uint *)(psVar5 + 4);
    uVar3 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
    uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
    if (sVar2 != 0x5942) {
      uVar3 = uVar1;
    }
    if (uVar3 != 0) {
      pcVar6 = (char *)((long)psVar5 + (long)(int)uVar3);
      if (*pcVar6 == -0x3b) {
        uVar1 = *(uint *)(pcVar6 + 4);
        uVar3 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
        uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
        if (sVar2 != 0x5942) {
          uVar3 = uVar1;
        }
        lVar7 = *(long *)(pcVar6 + uVar3);
      }
      else {
        lVar7 = 0;
      }
      uVar1 = *(uint *)(pcVar6 + ((long)(auVar8._8_8_ << 0x20) >> 0x1e) + 4);
      *param_1 = (long)param_1 + 0xc;
      *(undefined1 *)((long)param_1 + 0x4b) = 0;
      uVar3 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
      uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
      if (sVar2 != 0x5942) {
        uVar3 = uVar1;
      }
      pcVar6 = pcVar6 + (ulong)uVar3 + lVar7;
      goto LAB_7101551a6c;
    }
  }
  *(undefined1 *)((long)param_1 + 0x4b) = 0;
  pcVar6 = "";
  *param_1 = (long)param_1 + 0xc;
LAB_7101551a6c:
  *(undefined4 *)(param_1 + 1) = 0x40;
  if ((char *)((long)param_1 + 0xc) != pcVar6) {
    if (*pcVar6 == '\0') {
LAB_7101551ab0:
      lVar7 = 0;
    }
    else {
      lVar7 = 0;
      do {
        if (lVar7 == 0x400000) goto LAB_7101551ab0;
        if (pcVar6[lVar7 + 1] == '\0') {
          lVar7 = lVar7 + 1;
          if ((int)lVar7 < 0x40) goto LAB_7101551ac8;
          goto LAB_7101551ac4;
        }
        lVar4 = lVar7 + 2;
        lVar7 = lVar7 + 2;
      } while (pcVar6[lVar4] != '\0');
      if (0x3f < (int)lVar7) {
LAB_7101551ac4:
        lVar7 = 0x3f;
      }
    }
LAB_7101551ac8:
    thunk_EXT_FUN_02e95df0();
    *(undefined1 *)((long)param_1 + (long)(int)lVar7 + 0xc) = 0;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_7101551d90(long param_1,int param_2,undefined8 *param_3)

{
  uint uVar1;
  short sVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  int iVar6;
  short *psVar7;
  long lVar8;
  undefined8 uVar9;
  char *pcVar10;
  char *pcVar11;
  ulong uVar12;
  uint uVar13;
  undefined1 auVar14 [16];
  undefined8 local_60;
  uint local_58;
  uint local_54;
  
  if (*(long *)(param_1 + 8) == 0) {
    return 0xffffffff;
  }
  if (((DAT_710407a420 & 1) == 0) && (iVar6 = thunk_EXT_FUN_02e95df0(&DAT_710407a420), iVar6 != 0))
  {
    DAT_710407a410 = 0;
    DAT_710407a418 = 0;
    _DAT_710407a41c = _DAT_710407a41c & 0xffffff00;
    thunk_EXT_FUN_02e95df0(&DAT_710407a420);
  }
  lVar8 = *(long *)(param_1 + 8);
  if (lVar8 == 0) {
LAB_7101551e18:
    local_60._0_5_ = (undefined5)DAT_710407a410;
    local_60._5_3_ = (undefined3)((ulong)DAT_710407a410 >> 0x28);
    local_58 = DAT_710407a418;
    local_54 = _DAT_710407a41c;
  }
  else {
    if (param_2 == 2) {
      local_60._0_5_ = 0;
      local_60._5_3_ = 0;
      local_58 = 0;
      local_54 = (uint)local_54._1_3_ << 8;
      if ((*(byte *)(lVar8 + 0xac) & 0xf7) != 0xc0) goto LAB_7101551e84;
      local_60._0_5_ = (undefined5)*(undefined8 *)(lVar8 + 0xa0);
      uVar9 = *(undefined8 *)(lVar8 + 0xa5);
    }
    else if (param_2 == 1) {
      local_60._0_5_ = 0;
      local_60._5_3_ = 0;
      local_58 = 0;
      local_54 = (uint)local_54._1_3_ << 8;
      if ((*(byte *)(lVar8 + 0x9c) & 0xf7) != 0xc0) goto LAB_7101551e84;
      local_60._0_5_ = (undefined5)*(undefined8 *)(lVar8 + 0x90);
      uVar9 = *(undefined8 *)(lVar8 + 0x95);
    }
    else {
      if (param_2 != 0) goto LAB_7101551e18;
      local_60._0_5_ = 0;
      local_60._5_3_ = 0;
      local_58 = 0;
      local_54 = local_54 & 0xffffff00;
      if ((*(byte *)(lVar8 + 0x8c) & 0xf7) != 0xc0) goto LAB_7101551e84;
      local_60._0_5_ = (undefined5)*(undefined8 *)(lVar8 + 0x80);
      uVar9 = *(undefined8 *)(lVar8 + 0x85);
    }
    local_60._5_3_ = (undefined3)uVar9;
    local_58 = (uint)((ulong)uVar9 >> 0x18);
    local_54._0_1_ = (undefined1)((ulong)uVar9 >> 0x38);
  }
LAB_7101551e84:
  if (((((local_54 & 0xf7) == 0xc0) || ((local_54 & 0xff) == 0xc1)) || ((local_54 & 0xff) == 0xc4))
     || ((local_54 & 0xe0) == 0x20)) {
    uVar13 = *(uint *)((long)CONCAT35(local_60._5_3_,(undefined5)local_60) + (ulong)local_58);
    uVar3 = uVar13 >> 8;
    if (*(short *)CONCAT35(local_60._5_3_,(undefined5)local_60) == 0x5942) {
      uVar3 = uVar3 & 0xff00 | uVar13 >> 0x18 | (uVar3 & 0xff) << 0x10;
    }
    if (uVar3 != 0) {
      uVar13 = 0;
      do {
        auVar14 = FUN_71028132dc(&local_60,uVar13);
        psVar7 = auVar14._0_8_;
        pcVar10 = "";
        if ((auVar14._8_8_ & 0xff00000000) == 0xa000000000) {
          sVar2 = *psVar7;
          uVar1 = *(uint *)(psVar7 + 4);
          uVar4 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
          uVar4 = uVar4 >> 0x10 | uVar4 << 0x10;
          if (sVar2 != 0x5942) {
            uVar4 = uVar1;
          }
          if (uVar4 == 0) {
            pcVar10 = "";
          }
          else {
            pcVar10 = (char *)((long)psVar7 + (long)(int)uVar4);
            if (*pcVar10 == -0x3b) {
              uVar1 = *(uint *)(pcVar10 + 4);
              uVar4 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
              uVar4 = uVar4 >> 0x10 | uVar4 << 0x10;
              if (sVar2 != 0x5942) {
                uVar4 = uVar1;
              }
              lVar8 = *(long *)(pcVar10 + uVar4);
            }
            else {
              lVar8 = 0;
            }
            uVar1 = *(uint *)(pcVar10 + ((long)(auVar14._8_8_ << 0x20) >> 0x1e) + 4);
            uVar4 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
            uVar4 = uVar4 >> 0x10 | uVar4 << 0x10;
            if (sVar2 != 0x5942) {
              uVar4 = uVar1;
            }
            pcVar10 = pcVar10 + (ulong)uVar4 + lVar8;
          }
        }
        pcVar11 = (char *)*param_3;
        if (pcVar10 == pcVar11) {
          return 1;
        }
        bVar5 = true;
        for (uVar12 = 0; pcVar10[uVar12] == pcVar11[uVar12]; uVar12 = uVar12 + 2) {
          if (pcVar10[uVar12] == '\0') {
LAB_7101551f00:
            if (bVar5) {
              return 1;
            }
            break;
          }
          if ((uVar12 == 0x400000) || (pcVar10[uVar12 + 1] != pcVar11[uVar12 + 1])) break;
          if (pcVar10[uVar12 + 1] == '\0') {
            bVar5 = uVar12 < 0x400000;
            goto LAB_7101551f00;
          }
          bVar5 = uVar12 + 1 < 0x400000;
        }
        uVar13 = uVar13 + 1;
        if (uVar3 == uVar13) {
          return 0xffffffff;
        }
      } while( true );
    }
  }
  return 0xffffffff;
}



byte FUN_710155205c(long param_1,undefined8 *param_2,undefined8 *param_3,undefined8 *param_4)

{
  uint uVar1;
  uint uVar2;
  bool bVar3;
  undefined8 uVar4;
  long lVar5;
  byte bVar6;
  byte bVar7;
  
  lVar5 = *(long *)(param_1 + 8);
  if (lVar5 == 0) {
    return 0;
  }
  if (*(char *)*param_2 == '\0') {
    if ((*(byte *)(lVar5 + 0x8c) & 0xf7) == 0xc0) {
      uVar1 = *(uint *)((long)*(short **)(lVar5 + 0x80) + (ulong)*(uint *)(lVar5 + 0x88));
      uVar2 = uVar1 >> 8;
      if (**(short **)(lVar5 + 0x80) == 0x5942) {
        uVar2 = uVar2 & 0xff00 | uVar1 >> 0x18 | (uVar2 & 0xff) << 0x10;
      }
      if (uVar2 != 0) goto LAB_71015520e8;
    }
LAB_71015520fc:
    bVar7 = 1;
    lVar5 = *(long *)(param_1 + 8);
  }
  else {
    uVar4 = FUN_7101551d90(param_1,0,param_2);
    if ((int)uVar4 != -1) goto LAB_71015520fc;
LAB_71015520e8:
    bVar7 = 0;
    lVar5 = *(long *)(param_1 + 8);
  }
  if (lVar5 == 0) {
    bVar6 = 0;
    bVar3 = false;
  }
  else {
    bVar6 = bVar7;
    if (*(char *)*param_3 != '\0') {
      uVar4 = FUN_7101551d90(param_1,1,param_3);
      bVar6 = 0;
      if ((int)uVar4 != -1) {
        bVar6 = bVar7;
      }
      bVar3 = false;
      if (*(long *)(param_1 + 8) == 0) goto LAB_7101552160;
    }
    if (*(char *)*param_4 == '\0') {
      bVar3 = true;
    }
    else {
      uVar4 = FUN_7101551d90(param_1,2,param_4);
      bVar3 = (int)uVar4 != -1;
    }
  }
LAB_7101552160:
  return bVar6 & bVar3;
}



bool FUN_710155217c(long param_1,long param_2,uint param_3,undefined8 param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  bool bVar2;
  long lVar3;
  undefined8 uVar4;
  undefined1 auVar5 [16];
  undefined1 *local_60;
  int local_58;
  undefined1 local_54 [31];
  undefined1 local_35;
  undefined8 local_30;
  undefined4 local_28;
  undefined1 local_24;
  uint local_4;
  
  bVar2 = false;
  if ((param_2 != 0) && (param_3 < 100)) {
    lVar3 = *(long *)(param_1 + 8);
    local_30._0_5_ = 0;
    local_30._5_3_ = 0;
    local_28 = 0;
    local_24 = 0;
    if ((*(char *)(lVar3 + 0xdc) == -0x3c) || (*(char *)(lVar3 + 0xdc) == -0x3f)) {
      local_30._0_5_ = (undefined5)*(undefined8 *)(lVar3 + 0xd0);
      uVar4 = *(undefined8 *)(lVar3 + 0xd5);
      local_30._5_3_ = (undefined3)uVar4;
      local_28 = (undefined4)((ulong)uVar4 >> 0x18);
      local_24 = (undefined1)((ulong)uVar4 >> 0x38);
    }
    local_60 = local_54;
    local_35 = 0;
    local_54[0] = 0;
    local_58 = 0x20;
    local_4 = param_3;
    FUN_7100ca4c30((long *)&local_60,0x710313d163,&local_4,param_4,param_5,param_6,param_7,param_8);
    local_60[(long)local_58 + -1] = 0;
    auVar5 = FUN_7102813520(&local_30,local_60);
    bVar2 = false;
    if (auVar5._0_8_ != 0) {
      uVar1 = auVar5._12_4_ & 0xff;
      if ((uVar1 == 0xc4) || (uVar1 == 0xc1)) {
        *(long *)(param_2 + 8) = auVar5._0_8_;
        *(int *)(param_2 + 0x10) = auVar5._8_4_;
        *(char *)(param_2 + 0x14) = auVar5[0xc];
      }
      bVar2 = uVar1 == 0xc1 || uVar1 == 0xc4;
    }
  }
  return bVar2;
}



undefined8 FUN_7101552270(long param_1,undefined8 *param_2)

{
  char *pcVar1;
  int iVar2;
  char cVar3;
  short sVar4;
  uint uVar5;
  int *piVar6;
  uint uVar7;
  uint uVar8;
  short *psVar9;
  long lVar10;
  int iVar11;
  
  cVar3 = *(char *)((long)param_2 + 0xc);
  if (cVar3 == -0x2d) {
    uVar8 = *(uint *)(param_2 + 1);
  }
  else {
    if (cVar3 != -0x2f) {
      if (cVar3 != -0x60) {
        return 0;
      }
      psVar9 = (short *)*param_2;
      sVar4 = *psVar9;
      uVar5 = *(uint *)(psVar9 + 4);
      uVar8 = (uVar5 & 0xff00ff00) >> 8 | (uVar5 & 0xff00ff) << 8;
      uVar8 = uVar8 >> 0x10 | uVar8 << 0x10;
      if (sVar4 != 0x5942) {
        uVar8 = uVar5;
      }
      if (uVar8 == 0) {
        return 0;
      }
      pcVar1 = (char *)((long)psVar9 + (long)(int)uVar8);
      if (*pcVar1 == -0x3b) {
        uVar5 = *(uint *)(pcVar1 + 4);
        uVar8 = (uVar5 & 0xff00ff00) >> 8 | (uVar5 & 0xff00ff) << 8;
        uVar8 = uVar8 >> 0x10 | uVar8 << 0x10;
        if (sVar4 != 0x5942) {
          uVar8 = uVar5;
        }
        lVar10 = *(long *)(pcVar1 + uVar8);
      }
      else {
        lVar10 = 0;
      }
      uVar5 = *(uint *)(pcVar1 + (long)*(int *)(param_2 + 1) * 4 + 4);
      uVar8 = (uVar5 & 0xff00ff00) >> 8 | (uVar5 & 0xff00ff) << 8;
      uVar8 = uVar8 >> 0x10 | uVar8 << 0x10;
      if (sVar4 != 0x5942) {
        uVar8 = uVar5;
      }
      uVar5 = FUN_7100bb2120((byte *)(pcVar1 + (ulong)uVar8 + lVar10),0);
      piVar6 = *(int **)(param_1 + 8);
      uVar8 = 0;
      iVar11 = 0xb;
      do {
        iVar2 = iVar11 + uVar8;
        if (iVar2 < 0 != SCARRY4(iVar11,uVar8)) {
          iVar2 = iVar2 + 1;
        }
        uVar7 = iVar2 >> 1;
        if (*(uint *)(&DAT_71032af548 + (long)*(int *)(&DAT_71032af578 + (long)(int)uVar7 * 4) * 4)
            == uVar5) {
          if ((int)uVar7 < 0) {
            return 0;
          }
          goto LAB_710155241c;
        }
        iVar2 = uVar7 - 1;
        if (uVar5 < *(uint *)(&DAT_71032af548 +
                             (long)*(int *)(&DAT_71032af578 + (long)(int)uVar7 * 4) * 4)) {
          uVar8 = uVar7 + 1;
          iVar2 = iVar11;
        }
        iVar11 = iVar2;
      } while ((int)uVar8 < iVar11);
      if (*(uint *)(&DAT_71032af548 + (long)*(int *)(&DAT_71032af578 + (long)(int)uVar8 * 4) * 4) !=
          uVar5) {
        return 0;
      }
      uVar7 = uVar8;
      if ((int)uVar8 < 0) {
        return 0;
      }
LAB_710155241c:
      iVar11 = *(int *)(&DAT_71032af578 + (ulong)uVar7 * 4);
      goto joined_r0x007101552374;
    }
    uVar8 = *(uint *)(param_2 + 1);
    if ((int)uVar8 < 0) {
      return 0;
    }
  }
  piVar6 = *(int **)(param_1 + 8);
  uVar5 = 0;
  iVar11 = 0xb;
  do {
    iVar2 = iVar11 + uVar5;
    if (iVar2 < 0 != SCARRY4(iVar11,uVar5)) {
      iVar2 = iVar2 + 1;
    }
    uVar7 = iVar2 >> 1;
    if (*(uint *)(&DAT_71032af548 + (long)*(int *)(&DAT_71032af578 + (long)(int)uVar7 * 4) * 4) ==
        uVar8) {
      if ((int)uVar7 < 0) {
        return 0;
      }
      goto LAB_710155236c;
    }
    iVar2 = uVar7 - 1;
    if (uVar8 < *(uint *)(&DAT_71032af548 +
                         (long)*(int *)(&DAT_71032af578 + (long)(int)uVar7 * 4) * 4)) {
      uVar5 = uVar7 + 1;
      iVar2 = iVar11;
    }
    iVar11 = iVar2;
  } while ((int)uVar5 < iVar11);
  if (*(uint *)(&DAT_71032af548 + (long)*(int *)(&DAT_71032af578 + (long)(int)uVar5 * 4) * 4) !=
      uVar8) {
    return 0;
  }
  uVar7 = uVar5;
  if ((int)uVar5 < 0) {
    return 0;
  }
LAB_710155236c:
  iVar11 = *(int *)(&DAT_71032af578 + (ulong)uVar7 * 4);
joined_r0x007101552374:
  if (iVar11 < 0) {
    return 0;
  }
  *piVar6 = iVar11;
  return 1;
}



undefined8 FUN_7101552444(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a62d40 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62d40), iVar1 != 0))
  {
    *DAT_7103a62d38 = DAT_7103a5a180 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62d40);
  }
  if (param_2 != DAT_7103a62d38) {
    if (((*DAT_7103a5a178 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a178), iVar1 != 0)
       ) {
      *DAT_7103a5a170 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a5a178);
    }
    if (param_2 != DAT_7103a5a170) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101552544(void)

{
  int iVar1;
  
  if (((*DAT_7103a62d40 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62d40), iVar1 != 0))
  {
    *DAT_7103a62d38 = DAT_7103a5a180 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62d40);
  }
  return DAT_7103a62d38;
}



void FUN_71015525a4(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015525e4. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101552770(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015527b0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 FUN_71015527d0(long param_1,undefined8 *param_2)

{
  char *pcVar1;
  char cVar2;
  short sVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  short *psVar8;
  long lVar9;
  ulong uVar10;
  int iVar11;
  
  cVar2 = *(char *)((long)param_2 + 0xc);
  if (cVar2 == -0x2d) {
    uVar6 = *(uint *)(param_2 + 1);
  }
  else {
    if (cVar2 != -0x2f) {
      if (cVar2 != -0x60) {
        return 0;
      }
      psVar8 = (short *)*param_2;
      sVar3 = *psVar8;
      uVar7 = *(uint *)(psVar8 + 4);
      uVar6 = (uVar7 & 0xff00ff00) >> 8 | (uVar7 & 0xff00ff) << 8;
      uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
      if (sVar3 != 0x5942) {
        uVar6 = uVar7;
      }
      if (uVar6 == 0) {
        return 0;
      }
      pcVar1 = (char *)((long)psVar8 + (long)(int)uVar6);
      if (*pcVar1 == -0x3b) {
        uVar7 = *(uint *)(pcVar1 + 4);
        uVar6 = (uVar7 & 0xff00ff00) >> 8 | (uVar7 & 0xff00ff) << 8;
        uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
        if (sVar3 != 0x5942) {
          uVar6 = uVar7;
        }
        lVar9 = *(long *)(pcVar1 + uVar6);
      }
      else {
        lVar9 = 0;
      }
      uVar7 = *(uint *)(pcVar1 + (long)*(int *)(param_2 + 1) * 4 + 4);
      uVar6 = (uVar7 & 0xff00ff00) >> 8 | (uVar7 & 0xff00ff) << 8;
      uVar6 = uVar6 >> 0x10 | uVar6 << 0x10;
      if (sVar3 != 0x5942) {
        uVar6 = uVar7;
      }
      uVar6 = FUN_7100bb2120((byte *)(pcVar1 + (ulong)uVar6 + lVar9),0);
      uVar10 = 0;
      iVar11 = 7;
      do {
        uVar7 = (uint)uVar10;
        uVar4 = iVar11 + uVar7 >> 1;
        uVar10 = (ulong)uVar4;
        if (*(uint *)(&DAT_71032af5a8 + (long)*(int *)(&DAT_71032af5c8 + uVar10 * 4) * 4) == uVar6)
        goto LAB_7101552974;
        iVar5 = uVar4 - 1;
        if (uVar6 < *(uint *)(&DAT_71032af5a8 + (long)*(int *)(&DAT_71032af5c8 + uVar10 * 4) * 4)) {
          uVar7 = uVar4 + 1;
          iVar5 = iVar11;
        }
        iVar11 = iVar5;
        uVar10 = (ulong)uVar7;
      } while ((int)uVar7 < iVar11);
      if ((int)uVar7 < 0) {
        return 0;
      }
      if (*(uint *)(&DAT_71032af5a8 + (long)*(int *)(&DAT_71032af5c8 + (ulong)uVar7 * 4) * 4) !=
          uVar6) {
        return 0;
      }
LAB_7101552974:
      if (-1 < *(int *)(&DAT_71032af5c8 + uVar10 * 4)) {
        **(int **)(param_1 + 8) = *(int *)(&DAT_71032af5c8 + uVar10 * 4);
        return 1;
      }
      return 0;
    }
    uVar6 = *(uint *)(param_2 + 1);
    if ((int)uVar6 < 0) {
      return 0;
    }
  }
  uVar10 = 0;
  iVar11 = 7;
  do {
    uVar7 = (uint)uVar10;
    uVar4 = iVar11 + uVar7 >> 1;
    uVar10 = (ulong)uVar4;
    if (*(uint *)(&DAT_71032af5a8 + (long)*(int *)(&DAT_71032af5c8 + uVar10 * 4) * 4) == uVar6)
    goto LAB_71015528c4;
    iVar5 = uVar4 - 1;
    if (uVar6 < *(uint *)(&DAT_71032af5a8 + (long)*(int *)(&DAT_71032af5c8 + uVar10 * 4) * 4)) {
      uVar7 = uVar4 + 1;
      iVar5 = iVar11;
    }
    iVar11 = iVar5;
    uVar10 = (ulong)uVar7;
  } while ((int)uVar7 < iVar11);
  if ((int)uVar7 < 0) {
    return 0;
  }
  if (*(uint *)(&DAT_71032af5a8 + (long)*(int *)(&DAT_71032af5c8 + (ulong)uVar7 * 4) * 4) != uVar6)
  {
    return 0;
  }
LAB_71015528c4:
  if (*(int *)(&DAT_71032af5c8 + uVar10 * 4) < 0) {
    return 0;
  }
  **(int **)(param_1 + 8) = *(int *)(&DAT_71032af5c8 + uVar10 * 4);
  return 1;
}



undefined8 FUN_710155299c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a62d60 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62d60), iVar1 != 0))
  {
    *DAT_7103a62d58 = DAT_7103a5a180 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62d60);
  }
  if (param_2 != DAT_7103a62d58) {
    if (((*DAT_7103a5a178 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a178), iVar1 != 0)
       ) {
      *DAT_7103a5a170 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a5a178);
    }
    if (param_2 != DAT_7103a5a170) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101552a9c(void)

{
  int iVar1;
  
  if (((*DAT_7103a62d60 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62d60), iVar1 != 0))
  {
    *DAT_7103a62d58 = DAT_7103a5a180 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62d60);
  }
  return DAT_7103a62d58;
}



void FUN_7101552afc(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101552b3c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 FUN_7101552d68(long param_1,undefined8 *param_2)

{
  char *pcVar1;
  uint uVar2;
  char cVar3;
  short sVar4;
  uint uVar5;
  int *piVar6;
  short *psVar7;
  ulong uVar8;
  long lVar9;
  
  cVar3 = *(char *)((long)param_2 + 0xc);
  if (cVar3 == -0x2d) {
    uVar5 = *(uint *)(param_2 + 1);
    piVar6 = *(int **)(param_1 + 8);
    if (uVar5 == 0xd9e40095) {
      uVar8 = 0;
      goto LAB_7101552ea8;
    }
  }
  else {
    if (cVar3 != -0x2f) {
      if (cVar3 != -0x60) {
        return 0;
      }
      psVar7 = (short *)*param_2;
      sVar4 = *psVar7;
      uVar2 = *(uint *)(psVar7 + 4);
      uVar5 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
      uVar5 = uVar5 >> 0x10 | uVar5 << 0x10;
      if (sVar4 != 0x5942) {
        uVar5 = uVar2;
      }
      if (uVar5 == 0) {
        return 0;
      }
      pcVar1 = (char *)((long)psVar7 + (long)(int)uVar5);
      if (*pcVar1 == -0x3b) {
        uVar2 = *(uint *)(pcVar1 + 4);
        uVar5 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
        uVar5 = uVar5 >> 0x10 | uVar5 << 0x10;
        if (sVar4 != 0x5942) {
          uVar5 = uVar2;
        }
        lVar9 = *(long *)(pcVar1 + uVar5);
      }
      else {
        lVar9 = 0;
      }
      uVar2 = *(uint *)(pcVar1 + (long)*(int *)(param_2 + 1) * 4 + 4);
      uVar5 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
      uVar5 = uVar5 >> 0x10 | uVar5 << 0x10;
      if (sVar4 != 0x5942) {
        uVar5 = uVar2;
      }
      uVar5 = FUN_7100bb2120((byte *)(pcVar1 + (ulong)uVar5 + lVar9),0);
      piVar6 = *(int **)(param_1 + 8);
      if (uVar5 == 0xd9e40095) {
        uVar8 = 0;
      }
      else {
        uVar8 = (ulong)(uVar5 < 0xd9e40095);
        if (*(uint *)(&DAT_71032af5e8 + (long)(int)(&DAT_71032af5f0)[uVar8] * 4) != uVar5) {
          return 0;
        }
      }
      goto LAB_7101552ea8;
    }
    uVar5 = *(uint *)(param_2 + 1);
    if ((int)uVar5 < 0) {
      return 0;
    }
    piVar6 = *(int **)(param_1 + 8);
  }
  uVar8 = (ulong)(uVar5 < 0xd9e40095);
  if (*(uint *)(&DAT_71032af5e8 + (long)(int)(&DAT_71032af5f0)[uVar8] * 4) != uVar5) {
    return 0;
  }
LAB_7101552ea8:
  if ((int)(&DAT_71032af5f0)[uVar8] < 0) {
    return 0;
  }
  *piVar6 = (&DAT_71032af5f0)[uVar8];
  return 1;
}



undefined8 FUN_7101552ed0(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a62d80 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62d80), iVar1 != 0))
  {
    *DAT_7103a62d78 = DAT_7103a5a180 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62d80);
  }
  if (param_2 != DAT_7103a62d78) {
    if (((*DAT_7103a5a178 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a5a178), iVar1 != 0)
       ) {
      *DAT_7103a5a170 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a5a178);
    }
    if (param_2 != DAT_7103a5a170) {
      param_1 = 0;
    }
  }
  return param_1;
}



long * FUN_7101552fd0(void)

{
  int iVar1;
  
  if (((*DAT_7103a62d80 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62d80), iVar1 != 0))
  {
    *DAT_7103a62d78 = DAT_7103a5a180 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a62d80);
  }
  return DAT_7103a62d78;
}



void FUN_7101553030(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101553070. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101553090(long param_1,long param_2)

{
  int iVar1;
  uint uVar2;
  ulong uVar3;
  byte *local_80;
  int local_78;
  byte local_74 [63];
  undefined1 local_35;
  
  local_35 = 0;
  local_80 = local_74;
  local_78 = 0x40;
  local_74[0] = 0;
  iVar1 = (**(code **)(**(long **)(param_2 + 8) + 0x30))
                    (*(long **)(param_2 + 8),*(undefined8 *)(param_2 + 0x10),
                     *(undefined4 *)(param_2 + 0x18));
  if (iVar1 != 0) {
    (**(code **)(**(long **)(param_2 + 8) + 0x50))
              (*(long **)(param_2 + 8),*(undefined8 *)(param_2 + 0x10),&local_80,iVar1);
    local_80[(long)local_78 + -1] = 0;
    uVar2 = FUN_7100bb2120(local_80,0);
    if (uVar2 == 0xd9e40095) {
      uVar3 = 0;
    }
    else {
      uVar3 = (ulong)(uVar2 < 0xd9e40095);
      if (*(uint *)(&DAT_71032af5e8 + (long)(int)(&DAT_71032af5f0)[uVar3] * 4) != uVar2) {
        return;
      }
    }
    if (-1 < (int)(&DAT_71032af5f0)[uVar3]) {
      **(int **)(param_1 + 8) = (&DAT_71032af5f0)[uVar3];
    }
  }
  return;
}



void FUN_71015531c4(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101553204. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101553224(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101553264. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101553284(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015532c4. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71015532e4(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101553324. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101553344(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x007101553384. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71015533a4(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071015533e4. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_7101553410(long param_1,undefined8 *param_2)

{
  long lVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  long *plVar6;
  long *plVar7;
  byte *pbVar8;
  int iVar9;
  undefined8 *puVar10;
  long lVar11;
  long lVar12;
  uint local_60 [2];
  undefined8 local_58;
  
  pbVar8 = DAT_7103a61c30;
  plVar7 = DAT_7103a61c28;
  plVar6 = DAT_7103a59ec8;
  iVar9 = *(int *)(param_1 + 0x2c);
  if (0 < iVar9) {
    lVar12 = 0;
    lVar1 = DAT_7103a59e80 + 0x10;
    do {
      local_60[0] = *(uint *)(*(long *)(param_1 + 0x20) + lVar12 * 0x10);
      if (local_60[0] != 0) {
        local_58 = 0;
        puVar10 = *(undefined8 **)(*plVar6 + 0xa8);
        if (((*pbVar8 & 1) == 0) && (iVar9 = thunk_EXT_FUN_02e95df0(pbVar8), iVar9 != 0)) {
          *plVar7 = lVar1;
          thunk_EXT_FUN_02e95df0(pbVar8);
        }
        lVar11 = (**(code **)*puVar10)(puVar10,plVar7);
        if ((local_60[0] != 0) && (uVar2 = *(uint *)(lVar11 + 0x2c), uVar2 != 0)) {
          uVar4 = 0;
          if (uVar2 != 0) {
            uVar4 = local_60[0] / uVar2;
          }
          uVar4 = local_60[0] - uVar4 * uVar2;
          uVar5 = uVar4;
          do {
            uVar3 = *(uint *)(*(long *)(lVar11 + 0x20) +
                             (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
            if (uVar3 == local_60[0]) {
              local_58 = *(undefined8 *)(*(long *)(lVar11 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
              goto LAB_7101553474;
            }
            if (uVar3 == 0) break;
            uVar3 = 0;
            if ((int)(uVar5 + 1) < (int)uVar2) {
              uVar3 = uVar5 + 1;
            }
            uVar5 = uVar3;
          } while (uVar3 != uVar4);
        }
        local_58 = 0;
LAB_7101553474:
        (**(code **)*param_2)(param_2,local_60);
        iVar9 = *(int *)(param_1 + 0x2c);
      }
      lVar12 = lVar12 + 1;
    } while (lVar12 < iVar9);
  }
  return;
}



void FUN_7101553580(long *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  long *plVar6;
  int iVar7;
  undefined8 *puVar8;
  undefined4 *puVar9;
  long lVar10;
  
  plVar6 = DAT_7103a59ec8;
  uVar1 = *param_2;
  if (uVar1 != 0) {
    uVar2 = *(uint *)(*(long *)(*DAT_7103a59fd0 + 0x16408) + 0x14);
    if (uVar2 != 0) {
      uVar4 = 0;
      if (uVar2 != 0) {
        uVar4 = uVar1 / uVar2;
      }
      lVar10 = *(long *)(*(long *)(*DAT_7103a59fd0 + 0x16408) + 8);
      uVar4 = uVar1 - uVar4 * uVar2;
      uVar5 = uVar4;
      do {
        uVar3 = *(uint *)(lVar10 + (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4
                                   ));
        if (uVar3 == uVar1) {
          lVar10 = lVar10 + (long)(int)uVar5 * 0x10 + 4;
          goto LAB_7101553600;
        }
        if (uVar3 == 0) break;
        uVar3 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar3 = uVar5 + 1;
        }
        uVar5 = uVar3;
      } while (uVar3 != uVar4);
    }
  }
  lVar10 = 0;
LAB_7101553600:
  *param_1 = lVar10;
  param_1[1] = 0;
  puVar8 = *(undefined8 **)(*plVar6 + 0x158);
  lVar10 = 0;
  if (puVar8 != (undefined8 *)0x0) {
    if (((*DAT_7103a617f8 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a617f8), iVar7 != 0)
       ) {
      *DAT_7103a617f0 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a617f8);
    }
    lVar10 = (**(code **)*puVar8)(puVar8,DAT_7103a617f0);
  }
  uVar1 = *param_2;
  puVar9 = DAT_7103a61830;
  if ((uVar1 != 0) && (uVar2 = *(uint *)(lVar10 + 0x8c), uVar2 != 0)) {
    uVar4 = 0;
    if (uVar2 != 0) {
      uVar4 = uVar1 / uVar2;
    }
    uVar4 = uVar1 - uVar4 * uVar2;
    uVar5 = uVar4;
    do {
      uVar3 = *(uint *)(*(long *)(lVar10 + 0x80) +
                       (-(ulong)(uVar5 >> 0x1f) & 0xfffffff800000000 | (ulong)uVar5 << 3));
      if (uVar3 == uVar1) {
        puVar9 = (undefined4 *)(*(long *)(lVar10 + 0x80) + (long)(int)uVar5 * 8 + 4);
        break;
      }
      if (uVar3 == 0) break;
      uVar3 = 0;
      if ((int)(uVar5 + 1) < (int)uVar2) {
        uVar3 = uVar5 + 1;
      }
      uVar5 = uVar3;
    } while (uVar3 != uVar4);
  }
  *(undefined4 *)(param_1 + 1) = *puVar9;
  if (*param_1 != 0) {
    *(undefined4 *)((long)param_1 + 0xc) = *(undefined4 *)(*param_1 + 4);
  }
  return;
}
