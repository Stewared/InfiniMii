


void FUN_71006046cc(void)

{
                    // WARNING: Could not recover jumptable at 0x0071006046d8. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_7103ff3ca0)();
  return;
}



bool FUN_71006046dc(long *param_1)

{
  long lVar1;
  
  lVar1 = FUN_7100604790();
  *param_1 = lVar1;
  lVar1 = FUN_71006047a0();
  param_1[1] = lVar1;
  lVar1 = FUN_71006047b0();
  param_1[2] = lVar1;
  lVar1 = FUN_71006047c0();
  param_1[3] = lVar1;
  lVar1 = FUN_71006047d0();
  param_1[4] = lVar1;
  lVar1 = FUN_71006047e0();
  param_1[5] = lVar1;
  lVar1 = FUN_71006047f0();
  param_1[6] = lVar1;
  lVar1 = FUN_7100604800();
  param_1[7] = lVar1;
  return ((((((*param_1 != 0 && param_1[1] != 0) && param_1[2] != 0) && param_1[3] != 0) &&
           param_1[4] != 0) && param_1[5] != 0) && param_1[6] != 0) && lVar1 != 0;
}



bool FUN_710060476c(long *param_1)

{
  return *param_1 != 0;
}



undefined8 FUN_7100604780(void)

{
  return 1;
}



undefined8 FUN_7100604790(void)

{
  return DAT_7103a70ae0;
}



undefined8 FUN_71006047a0(void)

{
  return DAT_7103a70ae8;
}



undefined8 FUN_71006047b0(void)

{
  return DAT_7103a70af0;
}



undefined8 FUN_71006047c0(void)

{
  return DAT_7103a70af8;
}



undefined8 FUN_71006047d0(void)

{
  return DAT_7103a70b00;
}



undefined8 FUN_71006047e0(void)

{
  return DAT_7103a70b08;
}



undefined8 FUN_71006047f0(void)

{
  return DAT_7103a70b10;
}



undefined8 FUN_7100604800(void)

{
  return DAT_7103a70b18;
}



void FUN_710060480c(undefined8 param_1)

{
  thunk_EXT_FUN_02e95df0(param_1,0,0x3018);
  return;
}



void FUN_7100604818(undefined8 *param_1,undefined8 param_2,undefined8 param_3)

{
  *param_1 = param_2;
  param_1[1] = param_3;
  *(undefined1 *)(param_1 + 0x22) = 1;
  *(byte *)((long)param_1 + 0x111) = *(byte *)((long)param_1 + 0x111) | 1;
  return;
}



undefined8 * FUN_7100604834(void)

{
  int iVar1;
  
  if (((*DAT_7103a70b68 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a70b68), iVar1 != 0))
  {
    *DAT_7103a70b70 = 0;
    thunk_EXT_FUN_02e95df0(DAT_7103a70b68);
    return DAT_7103a70b70;
  }
  return DAT_7103a70b70;
}



void FUN_7100604894(undefined8 *param_1)

{
  *param_1 = &DAT_7103800830;
  return;
}
