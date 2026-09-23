#ifndef __arm__

#error "This sub-project is only for ARM architecture."

#endif

constexpr size_t UNKNOWN = 0;
#define GAME_VERSION 873
// 填入版本号，为去掉小数点的版本号
// UNKNOWN 表示暂时未知

#if GAME_VERSION == 873

// ==== MaxZoom ====
constexpr size_t BoardZoomAddr = 0x6E467C;                 // 高视角缩放
constexpr size_t BoardZoom2Addr = 0x6E4910;                // 高视角缩放 2
constexpr size_t LawnAppScreenWidthHeightAddr = 0x5A1454;  // 分辨率设置

// ==== AliasToID ====
constexpr size_t PlantNameMapperAddr = UNKNOWN;  // 植物名映射（10.3 起不需要）
constexpr int firstFreePlantID = UNKNOWN;        // 自定义植物 ID 起始值

// ==== CDNExpansion ====
constexpr size_t CDNLoadAddr = UNKNOWN;  // RTON 加载（名字 + 表 ID + 标志）

// ==== LogOutput ====
// 无后缀那个是变参 printf 形（cpp 里已实现），下面三个是本版其它日志输出入口（待适配）
constexpr size_t LogOutputFuncAddr = 0xFEDB0C;
constexpr size_t LogOutputFuncAddr_Simple = UNKNOWN;
constexpr size_t LogOutputFuncAddr_Struct = UNKNOWN;
constexpr size_t LogOutputFuncAddr_v2 = UNKNOWN;

// ==== PrimeGlyphCacheLimitation ====
constexpr size_t PrimeGlyphCacheAddr = UNKNOWN;  // 字符缓冲大小

// ==== RSBDecrypt ====
constexpr size_t RSBPathRecorderAddr = UNKNOWN;  // 数据包路径记录（换成本地解密文件）

// ==== WorldMapVerticalScrolling ====
constexpr size_t WorldMapDoMovementAddr = UNKNOWN;

// ==== HookResourceManagerFunc ====
constexpr size_t ResourceManagerFuncAddr = 0x5A90CC;  // 资源管理器

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = 0x5A8928;  // 暂停菜单显示

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = 0x4A0EB4;  // 图鉴状态更新
constexpr size_t NarrativeCheckAddr = 0xF5A350;      // 剧情检查
constexpr size_t TutorialCheckAddr = 0xF5B0C0;       // 教程检查

// ==== GeneralFunction（通用工具：SexyString/类型系统/实体动画）====
constexpr size_t CtxGetAddr = 0x1001564;           // 取全局解析上下文单例
constexpr size_t DirGetAddr = 0x1161EBC;           // 类型目录
constexpr size_t EntityListBindAddr = 0xDCB87C;    // 绑定 props+248 实体列表
constexpr size_t GetHandleAddr = 0xFF073C;         // 取句柄值（a1+4 位域）
constexpr size_t HandleResolveAddr = 0x1007204;    // 句柄解析为指针
constexpr size_t CtxResolveAddr = 0x1003580;       // 上下文解析
constexpr size_t RegistryGetAddr = 0x1161E68;      // RtClass 注册表单例
constexpr size_t RtClassCtorAddr = 0x1176D0C;      // RtClass 构造
constexpr size_t SexyStringAssignAddr = 0x2496BC;  // SexyString 赋值（dst, 字符数据, 长度）
constexpr size_t SexyStringCopyAddr = 0xFF07D0;    // SexyString 拷贝
constexpr size_t SexyStringCtorAddr = 0xFF060C;    // SexyString 构造
constexpr size_t SexyStringDtorAddr = 0xFF0710;    // SexyString 清理/析构
constexpr size_t SexyStringEmptyAddr = 0xFF0838;   // SexyString 是否为空
constexpr size_t SexyStringParseAddr = 0x100761C;  // SexyString 解析（a1=输出, a2=上下文, a3=源）
constexpr size_t ZombieAnimRigGetAddr = 0x70515C;  // 僵尸 AnimRig 解析（海鸥受击实证）

// ==== SnapdragonWarming ====
constexpr size_t PowerListFindAddr = 0x8D0E68;       // 列表按(type,sub)找 power
constexpr size_t SnapdragonLoadAddr = 0xA8E104;      // Snapdragon loader(vtable槽7)（hook 点）
constexpr size_t WarmingCompFactoryAddr = 0xA59754;  // 温暖组件附加工厂(类型63, 附加+返回组件)
constexpr size_t WarmingSetPropsAddr = 0x3F9EA0;     // 温暖 SetProps(拷贝配置到组件+272)

// ==== AshDeathrattleFix ====
constexpr size_t BullVeteranVtableAddr = 0x1AE0580;       // ZombieBullVeteran vtable——patch 槽183
constexpr size_t BullVtableAddr = 0x1AE01E0;              // ZombieBull vtable——patch 槽183
constexpr size_t DinoBullyVeteranVtableAddr = 0x1AE4C40;  // DinoBullyVeteran vtable——patch 槽183
constexpr size_t GargantuarDeathAddr = 0x793800;          // 巨人族槽183 死亡收尾
constexpr size_t ZCorpImpVtableAddr = 0x1AFAAEC;          // ZombieZCorpImp vtable——patch 槽183
constexpr size_t ZombieAnimPauseAddr = 0x635228;          // 动画对象+147 = mPaused（官方化灰暂停）

// ==== SpringBeanPFInvuln ====
// 与 ARM64 统一：改 vtable 槽 81 替换（patchVFTable），原函数直接调用，弃用代码 hook
// （代码 hook 会越界覆盖邻槽函数）
constexpr size_t IsPlantFoodActiveAddr = 0xDCDCD4;  // PF 状态查询（+232 || 实体槽86，官方检查）
constexpr size_t SpringBeanDieAddr = 0xA94A1C;      // vtable 槽 81 原函数（死亡回调）
constexpr size_t SpringBeanVtableAddr =
    0x1B1AA78;                          // SpringBean vtable 起点（0x1B1AA70 = itanium 头）
constexpr int kSpringBeanDieSlot = 81;  // 死亡回调槽位

// ==== CostumeSkinPort（高版本 skin 装扮搬运）====
// 只对 9.x 之前的版本有意义（高版本游戏自带），其余版本块里没有本段
// 方案：不改 CostumeItemType 布局（元素是 vector 内联 44B，无空隙），skin 标记直接写在原有的
// LayerName 字段里：值以 "skin:" 开头，冒号后是 PopAnimName。
constexpr size_t CostumeFindItemAddr = 0xFBF770;     // 按 CostumeID 查 item（stride 44）
constexpr size_t CostumeGetIdAddr = 0xFBFC90;        // 取当前 CostumeID（参数 = 植物类型名字符串）
constexpr size_t CostumeAnimRateGetAddr = 0x630DAC;  // 动画速率读取（obj+24 读到 +32 float）
constexpr size_t CostumeAnimRateSetAddr = 0x630DB8;  // 动画速率写入
constexpr size_t HotUIPlantAnimAddr = 0xDBC194;      // 商店 HotUI 植物动画（按名字建动画的预览）
constexpr uint64_t kHotUiPlantNameOff = 436;         // 控件上的植物名（resolveWeak 解析用）
constexpr uint64_t kHotUiLayerNameOff = 448;         // 装扮 LayerName（判定 skin 用）
constexpr size_t CostumePreviewCtorAddr = 0x570C4C;  // 图鉴/选卡卡片初始化（之后按植物覆盖 box）
constexpr size_t CostumeAnimApplierAddr = 0x8899AC;  // 动画创建 hook 点（名字解析后创建）
constexpr size_t CostumeSwitchAddr = 0x571BA8;       // 图鉴切换装扮入口（切换后重建动画）

#endif

#if GAME_VERSION == 941

// ==== MaxZoom ====
constexpr size_t BoardZoomAddr = UNKNOWN;
constexpr size_t BoardZoom2Addr = UNKNOWN;
constexpr size_t LawnAppScreenWidthHeightAddr = UNKNOWN;

// ==== AliasToID ====
constexpr size_t PlantNameMapperAddr = 0xD994B8;
constexpr int firstFreePlantID = 185;

// ==== CDNExpansion ====
constexpr size_t CDNLoadAddr = UNKNOWN;

// ==== LogOutput ====
constexpr size_t LogOutputFuncAddr = UNKNOWN;
constexpr size_t LogOutputFuncAddr_Simple = UNKNOWN;
constexpr size_t LogOutputFuncAddr_Struct = UNKNOWN;
constexpr size_t LogOutputFuncAddr_v2 = UNKNOWN;

// ==== PrimeGlyphCacheLimitation ====
constexpr size_t PrimeGlyphCacheAddr = UNKNOWN;

// ==== RSBDecrypt ====
constexpr size_t RSBPathRecorderAddr = UNKNOWN;

// ==== WorldMapVerticalScrolling ====
constexpr size_t WorldMapDoMovementAddr = 0x44E604;

// ==== HookResourceManagerFunc ====
constexpr size_t ResourceManagerFuncAddr = UNKNOWN;

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = UNKNOWN;

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = UNKNOWN;
constexpr size_t NarrativeCheckAddr = UNKNOWN;
constexpr size_t TutorialCheckAddr = UNKNOWN;

// ==== GeneralFunction ====
constexpr size_t CtxGetAddr = UNKNOWN;
constexpr size_t DirGetAddr = UNKNOWN;
constexpr size_t EntityListBindAddr = UNKNOWN;
constexpr size_t GetHandleAddr = UNKNOWN;
constexpr size_t HandleResolveAddr = UNKNOWN;
constexpr size_t CtxResolveAddr = UNKNOWN;
constexpr size_t RegistryGetAddr = UNKNOWN;
constexpr size_t RtClassCtorAddr = UNKNOWN;
constexpr size_t SexyStringAssignAddr = UNKNOWN;
constexpr size_t SexyStringCopyAddr = UNKNOWN;
constexpr size_t SexyStringCtorAddr = UNKNOWN;
constexpr size_t SexyStringDtorAddr = UNKNOWN;
constexpr size_t SexyStringEmptyAddr = UNKNOWN;
constexpr size_t SexyStringParseAddr = UNKNOWN;
constexpr size_t ZombieAnimRigGetAddr = UNKNOWN;

// ==== AshDeathrattleFix ====
constexpr size_t BullVeteranVtableAddr = UNKNOWN;
constexpr size_t BullVtableAddr = UNKNOWN;
constexpr size_t DinoBullyVeteranVtableAddr = UNKNOWN;
constexpr size_t GargantuarDeathAddr = UNKNOWN;
constexpr size_t ZCorpImpVtableAddr = UNKNOWN;
constexpr size_t ZombieAnimPauseAddr = UNKNOWN;

// ==== SpringBeanPFInvuln ====
constexpr size_t IsPlantFoodActiveAddr = UNKNOWN;
constexpr size_t SpringBeanDieAddr = UNKNOWN;
constexpr size_t SpringBeanVtableAddr = UNKNOWN;
constexpr int kSpringBeanDieSlot = 81;

#endif

#if GAME_VERSION == 961

// ==== MaxZoom ====
constexpr size_t BoardZoomAddr = UNKNOWN;
constexpr size_t BoardZoom2Addr = UNKNOWN;
constexpr size_t LawnAppScreenWidthHeightAddr = UNKNOWN;

// ==== AliasToID ====
constexpr size_t PlantNameMapperAddr = 0xDA5C58;
constexpr int firstFreePlantID = 188;

// ==== CDNExpansion ====
constexpr size_t CDNLoadAddr = UNKNOWN;

// ==== LogOutput ====
constexpr size_t LogOutputFuncAddr = UNKNOWN;
constexpr size_t LogOutputFuncAddr_Simple = UNKNOWN;
constexpr size_t LogOutputFuncAddr_Struct = UNKNOWN;
constexpr size_t LogOutputFuncAddr_v2 = UNKNOWN;

// ==== PrimeGlyphCacheLimitation ====
constexpr size_t PrimeGlyphCacheAddr = UNKNOWN;

// ==== RSBDecrypt ====
constexpr size_t RSBPathRecorderAddr = UNKNOWN;

// ==== WorldMapVerticalScrolling ====
constexpr size_t WorldMapDoMovementAddr = 0x441068;

// ==== HookResourceManagerFunc ====
constexpr size_t ResourceManagerFuncAddr = UNKNOWN;

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = UNKNOWN;

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = UNKNOWN;
constexpr size_t NarrativeCheckAddr = UNKNOWN;
constexpr size_t TutorialCheckAddr = UNKNOWN;

// ==== GeneralFunction ====
constexpr size_t CtxGetAddr = UNKNOWN;
constexpr size_t DirGetAddr = UNKNOWN;
constexpr size_t EntityListBindAddr = UNKNOWN;
constexpr size_t GetHandleAddr = UNKNOWN;
constexpr size_t HandleResolveAddr = UNKNOWN;
constexpr size_t CtxResolveAddr = UNKNOWN;
constexpr size_t RegistryGetAddr = UNKNOWN;
constexpr size_t RtClassCtorAddr = UNKNOWN;
constexpr size_t SexyStringAssignAddr = UNKNOWN;
constexpr size_t SexyStringCopyAddr = UNKNOWN;
constexpr size_t SexyStringCtorAddr = UNKNOWN;
constexpr size_t SexyStringDtorAddr = UNKNOWN;
constexpr size_t SexyStringEmptyAddr = UNKNOWN;
constexpr size_t SexyStringParseAddr = UNKNOWN;
constexpr size_t ZombieAnimRigGetAddr = UNKNOWN;

// ==== AshDeathrattleFix ====
constexpr size_t BullVeteranVtableAddr = UNKNOWN;
constexpr size_t BullVtableAddr = UNKNOWN;
constexpr size_t DinoBullyVeteranVtableAddr = UNKNOWN;
constexpr size_t GargantuarDeathAddr = UNKNOWN;
constexpr size_t ZCorpImpVtableAddr = UNKNOWN;
constexpr size_t ZombieAnimPauseAddr = UNKNOWN;

// ==== SpringBeanPFInvuln ====
constexpr size_t IsPlantFoodActiveAddr = UNKNOWN;
constexpr size_t SpringBeanDieAddr = UNKNOWN;
constexpr size_t SpringBeanVtableAddr = UNKNOWN;
constexpr int kSpringBeanDieSlot = 81;

#endif

#if GAME_VERSION == 981

// ==== MaxZoom ====
constexpr size_t BoardZoomAddr = UNKNOWN;
constexpr size_t BoardZoom2Addr = UNKNOWN;
constexpr size_t LawnAppScreenWidthHeightAddr = UNKNOWN;

// ==== AliasToID ====
constexpr size_t PlantNameMapperAddr = 0xDFC008;
constexpr int firstFreePlantID = 191;

// ==== CDNExpansion ====
constexpr size_t CDNLoadAddr = UNKNOWN;

// ==== LogOutput ====
constexpr size_t LogOutputFuncAddr = UNKNOWN;
constexpr size_t LogOutputFuncAddr_Simple = UNKNOWN;
constexpr size_t LogOutputFuncAddr_Struct = UNKNOWN;
constexpr size_t LogOutputFuncAddr_v2 = UNKNOWN;

// ==== PrimeGlyphCacheLimitation ====
constexpr size_t PrimeGlyphCacheAddr = 0x13FBA38;

// ==== RSBDecrypt ====
constexpr size_t RSBPathRecorderAddr = UNKNOWN;

// ==== WorldMapVerticalScrolling ====
constexpr size_t WorldMapDoMovementAddr = 0x483504;

// ==== HookResourceManagerFunc ====
constexpr size_t ResourceManagerFuncAddr = UNKNOWN;

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = UNKNOWN;

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = UNKNOWN;
constexpr size_t NarrativeCheckAddr = UNKNOWN;
constexpr size_t TutorialCheckAddr = UNKNOWN;

// ==== GeneralFunction ====
constexpr size_t CtxGetAddr = UNKNOWN;
constexpr size_t DirGetAddr = UNKNOWN;
constexpr size_t EntityListBindAddr = UNKNOWN;
constexpr size_t GetHandleAddr = UNKNOWN;
constexpr size_t HandleResolveAddr = UNKNOWN;
constexpr size_t CtxResolveAddr = UNKNOWN;
constexpr size_t RegistryGetAddr = UNKNOWN;
constexpr size_t RtClassCtorAddr = UNKNOWN;
constexpr size_t SexyStringAssignAddr = UNKNOWN;
constexpr size_t SexyStringCopyAddr = UNKNOWN;
constexpr size_t SexyStringCtorAddr = UNKNOWN;
constexpr size_t SexyStringDtorAddr = UNKNOWN;
constexpr size_t SexyStringEmptyAddr = UNKNOWN;
constexpr size_t SexyStringParseAddr = UNKNOWN;
constexpr size_t ZombieAnimRigGetAddr = UNKNOWN;

// ==== AshDeathrattleFix ====
constexpr size_t BullVeteranVtableAddr = UNKNOWN;
constexpr size_t BullVtableAddr = UNKNOWN;
constexpr size_t DinoBullyVeteranVtableAddr = UNKNOWN;
constexpr size_t GargantuarDeathAddr = UNKNOWN;
constexpr size_t ZCorpImpVtableAddr = UNKNOWN;
constexpr size_t ZombieAnimPauseAddr = UNKNOWN;

// ==== SpringBeanPFInvuln ====
constexpr size_t IsPlantFoodActiveAddr = UNKNOWN;
constexpr size_t SpringBeanDieAddr = UNKNOWN;
constexpr size_t SpringBeanVtableAddr = UNKNOWN;
constexpr int kSpringBeanDieSlot = 81;

#endif

#if GAME_VERSION == 1031

// ==== MaxZoom ====
constexpr size_t BoardZoomAddr = 0x88D3EC;
constexpr size_t BoardZoom2Addr = 0x88D670;
constexpr size_t LawnAppScreenWidthHeightAddr = 0x6E4030;

// ==== AliasToID ====
constexpr size_t PlantNameMapperAddr = UNKNOWN;
constexpr int firstFreePlantID = UNKNOWN;  // 高版本不需要

// ==== CDNExpansion ====
constexpr size_t CDNLoadAddr = 0x876CB0;

// ==== LogOutput ====
constexpr size_t LogOutputFuncAddr = 0x146DE24;
constexpr size_t LogOutputFuncAddr_Simple = 0x146E160;
constexpr size_t LogOutputFuncAddr_Struct = 0x146DFE4;
constexpr size_t LogOutputFuncAddr_v2 = 0x146E028;

// ==== PrimeGlyphCacheLimitation ====
constexpr size_t PrimeGlyphCacheAddr = 0x177ECF4;

// ==== RSBDecrypt ====
constexpr size_t RSBPathRecorderAddr = 0x16431A8;

// ==== WorldMapVerticalScrolling ====
constexpr size_t WorldMapScrollAddr = 0x523EF0;
constexpr size_t KeepCenterAddr = 0x52ABDC;
constexpr size_t ScrollInertanceAddr = 0x5359F4;

// ==== HookResourceManagerFunc ====
constexpr size_t ResourceManagerFuncAddr = 0x6EE218;

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = UNKNOWN;

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = UNKNOWN;
constexpr size_t NarrativeCheckAddr = UNKNOWN;
constexpr size_t TutorialCheckAddr = UNKNOWN;

// ==== GeneralFunction ====
constexpr size_t CtxGetAddr = UNKNOWN;
constexpr size_t DirGetAddr = UNKNOWN;
constexpr size_t EntityListBindAddr = UNKNOWN;
constexpr size_t GetHandleAddr = UNKNOWN;
constexpr size_t HandleResolveAddr = UNKNOWN;
constexpr size_t CtxResolveAddr = UNKNOWN;
constexpr size_t RegistryGetAddr = UNKNOWN;
constexpr size_t RtClassCtorAddr = UNKNOWN;
constexpr size_t SexyStringAssignAddr = UNKNOWN;
constexpr size_t SexyStringCopyAddr = UNKNOWN;
constexpr size_t SexyStringCtorAddr = UNKNOWN;
constexpr size_t SexyStringDtorAddr = UNKNOWN;
constexpr size_t SexyStringEmptyAddr = UNKNOWN;
constexpr size_t SexyStringParseAddr = UNKNOWN;
constexpr size_t ZombieAnimRigGetAddr = UNKNOWN;

// ==== AshDeathrattleFix ====
constexpr size_t BullVeteranVtableAddr = UNKNOWN;
constexpr size_t BullVtableAddr = UNKNOWN;
constexpr size_t DinoBullyVeteranVtableAddr = UNKNOWN;
constexpr size_t GargantuarDeathAddr = UNKNOWN;
constexpr size_t ZCorpImpVtableAddr = UNKNOWN;
constexpr size_t ZombieAnimPauseAddr = UNKNOWN;

// ==== SpringBeanPFInvuln ====
constexpr size_t IsPlantFoodActiveAddr = UNKNOWN;
constexpr size_t SpringBeanDieAddr = UNKNOWN;
constexpr size_t SpringBeanVtableAddr = UNKNOWN;
constexpr int kSpringBeanDieSlot = 81;

#endif

// 在此仿照如上格式再续写所需版本号偏移分类

// 各版本 RtonTableID
std::map<std::string, int> rtonTableIDs;

void rtonTableIDsLoader() {
#if GAME_VERSION == 941

  rtonTableIDs["ScratchSpace.rton"] = UNKNOWN;
  rtonTableIDs["UknRton.rton"] = UNKNOWN;
  rtonTableIDs["Version.rton"] = UNKNOWN;
  rtonTableIDs["Manifest.rton"] = UNKNOWN;
  rtonTableIDs["CDNConfig.rton"] = UNKNOWN;
  rtonTableIDs["ForceUpdateConfig.rton"] = UNKNOWN;
  rtonTableIDs["LiveConfig.rton"] = UNKNOWN;
  rtonTableIDs["StartupConfig.rton"] = UNKNOWN;
  rtonTableIDs["NewMapConversionMapping.rton"] = UNKNOWN;
  rtonTableIDs["OldMapDataMapping.rton"] = UNKNOWN;
  rtonTableIDs["PropertySheets.rton"] = UNKNOWN;
  rtonTableIDs["PersonalConfig.rton"] = UNKNOWN;
  rtonTableIDs["PinataTypes.rton"] = UNKNOWN;
  rtonTableIDs["PlantTypes.rton"] = UNKNOWN;
  rtonTableIDs["PlantLevels.rton"] = UNKNOWN;
  rtonTableIDs["PlantMastery.rton"] = UNKNOWN;
  rtonTableIDs["PlantPowerUps.rton"] = UNKNOWN;
  rtonTableIDs["PlantAlmanacData.rton"] = UNKNOWN;
  rtonTableIDs["PlantProperties.rton"] = UNKNOWN;
  rtonTableIDs["Powers.rton"] = UNKNOWN;
  rtonTableIDs["ZombieTypes.rton"] = UNKNOWN;
  rtonTableIDs["ZombieActions.rton"] = UNKNOWN;
  rtonTableIDs["ZombieProperties.rton"] = UNKNOWN;
  rtonTableIDs["CreatureTypes.rton"] = UNKNOWN;
  rtonTableIDs["ProjectileTypes.rton"] = UNKNOWN;
  rtonTableIDs["GridItemTypes.rton"] = UNKNOWN;
  rtonTableIDs["EffectObjectTypes.rton"] = UNKNOWN;
  rtonTableIDs["CollectableTypes.rton"] = UNKNOWN;
  rtonTableIDs["PresentTableTypes.rton"] = UNKNOWN;
  rtonTableIDs["PresentTypes.rton"] = UNKNOWN;
  rtonTableIDs["PlantFamilyTypes.rton"] = UNKNOWN;
  rtonTableIDs["Quests.rton"] = UNKNOWN;
  rtonTableIDs["QuestsCategories.rton"] = UNKNOWN;
  rtonTableIDs["LoadingText.rton"] = UNKNOWN;
  rtonTableIDs["QuestThemes.rton"] = UNKNOWN;
  rtonTableIDs["QuestsActive.rton"] = UNKNOWN;
  rtonTableIDs["DailyQuests.rton"] = UNKNOWN;
  rtonTableIDs["DailyQuestData.rton"] = UNKNOWN;
  rtonTableIDs["UIWidgetSheets.rton"] = UNKNOWN;
  rtonTableIDs["NPCDataSheets.rton"] = UNKNOWN;
  rtonTableIDs["LevelModules.rton"] = UNKNOWN;
  rtonTableIDs["HeroTypes.rton"] = UNKNOWN;
  rtonTableIDs["PowerupTypes.rton"] = UNKNOWN;
  rtonTableIDs["GameFeatures.rton"] = UNKNOWN;
  rtonTableIDs["ToolPackets.rton"] = UNKNOWN;
  rtonTableIDs["StreamingMusic.rton"] = UNKNOWN;
  rtonTableIDs["Products.rton"] = UNKNOWN;
  rtonTableIDs["MarketLayout.rton"] = UNKNOWN;
  rtonTableIDs["MarketSchedule.rton"] = UNKNOWN;
  rtonTableIDs["RAPSchedule.rton"] = UNKNOWN;
  rtonTableIDs["DailyQuestSchedule.rton"] = UNKNOWN;
  rtonTableIDs["PlayerSegments.rton"] = UNKNOWN;
  rtonTableIDs["BoardGridMaps.rton"] = UNKNOWN;
  rtonTableIDs["LevelModulesDifficulty.rton"] = UNKNOWN;
  rtonTableIDs["LevelMutatorModules.rton"] = UNKNOWN;
  rtonTableIDs["LevelMutatorTables.rton"] = UNKNOWN;

#endif

#if GAME_VERSION == 961

  rtonTableIDs["ScratchSpace.rton"] = UNKNOWN;
  rtonTableIDs["UknRton.rton"] = UNKNOWN;
  rtonTableIDs["Version.rton"] = UNKNOWN;
  rtonTableIDs["Manifest.rton"] = UNKNOWN;
  rtonTableIDs["CDNConfig.rton"] = UNKNOWN;
  rtonTableIDs["ForceUpdateConfig.rton"] = UNKNOWN;
  rtonTableIDs["LiveConfig.rton"] = UNKNOWN;
  rtonTableIDs["StartupConfig.rton"] = UNKNOWN;
  rtonTableIDs["NewMapConversionMapping.rton"] = UNKNOWN;
  rtonTableIDs["OldMapDataMapping.rton"] = UNKNOWN;
  rtonTableIDs["PropertySheets.rton"] = UNKNOWN;
  rtonTableIDs["PersonalConfig.rton"] = UNKNOWN;
  rtonTableIDs["PinataTypes.rton"] = UNKNOWN;
  rtonTableIDs["PlantTypes.rton"] = UNKNOWN;
  rtonTableIDs["PlantLevels.rton"] = UNKNOWN;
  rtonTableIDs["PlantMastery.rton"] = UNKNOWN;
  rtonTableIDs["PlantPowerUps.rton"] = UNKNOWN;
  rtonTableIDs["PlantAlmanacData.rton"] = UNKNOWN;
  rtonTableIDs["PlantProperties.rton"] = UNKNOWN;
  rtonTableIDs["Powers.rton"] = UNKNOWN;
  rtonTableIDs["ZombieTypes.rton"] = UNKNOWN;
  rtonTableIDs["ZombieActions.rton"] = UNKNOWN;
  rtonTableIDs["ZombieProperties.rton"] = UNKNOWN;
  rtonTableIDs["CreatureTypes.rton"] = UNKNOWN;
  rtonTableIDs["ProjectileTypes.rton"] = UNKNOWN;
  rtonTableIDs["GridItemTypes.rton"] = UNKNOWN;
  rtonTableIDs["EffectObjectTypes.rton"] = UNKNOWN;
  rtonTableIDs["CollectableTypes.rton"] = UNKNOWN;
  rtonTableIDs["PresentTableTypes.rton"] = UNKNOWN;
  rtonTableIDs["PresentTypes.rton"] = UNKNOWN;
  rtonTableIDs["PlantFamilyTypes.rton"] = UNKNOWN;
  rtonTableIDs["Quests.rton"] = UNKNOWN;
  rtonTableIDs["QuestsCategories.rton"] = UNKNOWN;
  rtonTableIDs["LoadingText.rton"] = UNKNOWN;
  rtonTableIDs["QuestThemes.rton"] = UNKNOWN;
  rtonTableIDs["QuestsActive.rton"] = UNKNOWN;
  rtonTableIDs["DailyQuests.rton"] = UNKNOWN;
  rtonTableIDs["DailyQuestData.rton"] = UNKNOWN;
  rtonTableIDs["UIWidgetSheets.rton"] = UNKNOWN;
  rtonTableIDs["NPCDataSheets.rton"] = UNKNOWN;
  rtonTableIDs["LevelModules.rton"] = UNKNOWN;
  rtonTableIDs["HeroTypes.rton"] = UNKNOWN;
  rtonTableIDs["PowerupTypes.rton"] = UNKNOWN;
  rtonTableIDs["GameFeatures.rton"] = UNKNOWN;
  rtonTableIDs["ToolPackets.rton"] = UNKNOWN;
  rtonTableIDs["StreamingMusic.rton"] = UNKNOWN;
  rtonTableIDs["Products.rton"] = UNKNOWN;
  rtonTableIDs["MarketLayout.rton"] = UNKNOWN;
  rtonTableIDs["MarketSchedule.rton"] = UNKNOWN;
  rtonTableIDs["RAPSchedule.rton"] = UNKNOWN;
  rtonTableIDs["DailyQuestSchedule.rton"] = UNKNOWN;
  rtonTableIDs["PlayerSegments.rton"] = UNKNOWN;
  rtonTableIDs["BoardGridMaps.rton"] = UNKNOWN;
  rtonTableIDs["LevelModulesDifficulty.rton"] = UNKNOWN;
  rtonTableIDs["LevelMutatorModules.rton"] = UNKNOWN;
  rtonTableIDs["LevelMutatorTables.rton"] = UNKNOWN;

#endif

#if GAME_VERSION == 981

  rtonTableIDs["ScratchSpace.rton"] = UNKNOWN;
  rtonTableIDs["UknRton.rton"] = UNKNOWN;
  rtonTableIDs["Version.rton"] = UNKNOWN;
  rtonTableIDs["Manifest.rton"] = UNKNOWN;
  rtonTableIDs["CDNConfig.rton"] = UNKNOWN;
  rtonTableIDs["ForceUpdateConfig.rton"] = UNKNOWN;
  rtonTableIDs["LiveConfig.rton"] = UNKNOWN;
  rtonTableIDs["StartupConfig.rton"] = UNKNOWN;
  rtonTableIDs["NewMapConversionMapping.rton"] = UNKNOWN;
  rtonTableIDs["OldMapDataMapping.rton"] = UNKNOWN;
  rtonTableIDs["PropertySheets.rton"] = UNKNOWN;
  rtonTableIDs["PersonalConfig.rton"] = UNKNOWN;
  rtonTableIDs["PinataTypes.rton"] = UNKNOWN;
  rtonTableIDs["PlantTypes.rton"] = UNKNOWN;
  rtonTableIDs["PlantLevels.rton"] = UNKNOWN;
  rtonTableIDs["PlantMastery.rton"] = UNKNOWN;
  rtonTableIDs["PlantPowerUps.rton"] = UNKNOWN;
  rtonTableIDs["PlantAlmanacData.rton"] = UNKNOWN;
  rtonTableIDs["PlantProperties.rton"] = UNKNOWN;
  rtonTableIDs["Powers.rton"] = UNKNOWN;
  rtonTableIDs["ZombieTypes.rton"] = UNKNOWN;
  rtonTableIDs["ZombieActions.rton"] = UNKNOWN;
  rtonTableIDs["ZombieProperties.rton"] = UNKNOWN;
  rtonTableIDs["CreatureTypes.rton"] = UNKNOWN;
  rtonTableIDs["ProjectileTypes.rton"] = UNKNOWN;
  rtonTableIDs["GridItemTypes.rton"] = UNKNOWN;
  rtonTableIDs["EffectObjectTypes.rton"] = UNKNOWN;
  rtonTableIDs["CollectableTypes.rton"] = UNKNOWN;
  rtonTableIDs["PresentTableTypes.rton"] = UNKNOWN;
  rtonTableIDs["PresentTypes.rton"] = UNKNOWN;
  rtonTableIDs["PlantFamilyTypes.rton"] = UNKNOWN;
  rtonTableIDs["Quests.rton"] = UNKNOWN;
  rtonTableIDs["QuestsCategories.rton"] = UNKNOWN;
  rtonTableIDs["LoadingText.rton"] = UNKNOWN;
  rtonTableIDs["QuestThemes.rton"] = UNKNOWN;
  rtonTableIDs["QuestsActive.rton"] = UNKNOWN;
  rtonTableIDs["DailyQuests.rton"] = UNKNOWN;
  rtonTableIDs["DailyQuestData.rton"] = UNKNOWN;
  rtonTableIDs["UIWidgetSheets.rton"] = UNKNOWN;
  rtonTableIDs["NPCDataSheets.rton"] = UNKNOWN;
  rtonTableIDs["LevelModules.rton"] = UNKNOWN;
  rtonTableIDs["HeroTypes.rton"] = UNKNOWN;
  rtonTableIDs["PowerupTypes.rton"] = UNKNOWN;
  rtonTableIDs["GameFeatures.rton"] = UNKNOWN;
  rtonTableIDs["ToolPackets.rton"] = UNKNOWN;
  rtonTableIDs["StreamingMusic.rton"] = UNKNOWN;
  rtonTableIDs["Products.rton"] = UNKNOWN;
  rtonTableIDs["MarketLayout.rton"] = UNKNOWN;
  rtonTableIDs["MarketSchedule.rton"] = UNKNOWN;
  rtonTableIDs["RAPSchedule.rton"] = UNKNOWN;
  rtonTableIDs["DailyQuestSchedule.rton"] = UNKNOWN;
  rtonTableIDs["PlayerSegments.rton"] = UNKNOWN;
  rtonTableIDs["BoardGridMaps.rton"] = UNKNOWN;
  rtonTableIDs["LevelModulesDifficulty.rton"] = UNKNOWN;
  rtonTableIDs["LevelMutatorModules.rton"] = UNKNOWN;
  rtonTableIDs["LevelMutatorTables.rton"] = UNKNOWN;

#endif

#if GAME_VERSION == 1031

  rtonTableIDs["ScratchSpace.rton"] = 0;
  rtonTableIDs["UknRton.rton"] = 1;
  rtonTableIDs["Version.rton"] = 2;
  rtonTableIDs["Manifest.rton"] = 3;
  rtonTableIDs["CDNConfig.rton"] = 4;
  rtonTableIDs["ForceUpdateConfig.rton"] = 5;
  rtonTableIDs["LiveConfig.rton"] = 6;
  rtonTableIDs["StartupConfig.rton"] = 7;
  rtonTableIDs["NewMapConversionMapping.rton"] = 8;
  rtonTableIDs["OldMapDataMapping.rton"] = 9;
  rtonTableIDs["PropertySheets.rton"] = 10;
  rtonTableIDs["PersonalConfig.rton"] = 11;
  rtonTableIDs["PinataTypes.rton"] = 12;
  rtonTableIDs["PlantTypes.rton"] = 13;
  rtonTableIDs["PlantLevels.rton"] = 14;
  rtonTableIDs["PlantMastery.rton"] = 15;
  rtonTableIDs["PlantPowerUps.rton"] = 16;
  rtonTableIDs["PlantAlmanacData.rton"] = 17;
  rtonTableIDs["PlantProperties.rton"] = 18;
  rtonTableIDs["Powers.rton"] = 19;
  rtonTableIDs["ZombieTypes.rton"] = 20;
  rtonTableIDs["ZombieActions.rton"] = 21;
  rtonTableIDs["ZombieProperties.rton"] = 22;
  rtonTableIDs["CreatureTypes.rton"] = 23;
  rtonTableIDs["ProjectileTypes.rton"] = 24;
  rtonTableIDs["GridItemTypes.rton"] = 25;
  rtonTableIDs["EffectObjectTypes.rton"] = 26;
  rtonTableIDs["CollectableTypes.rton"] = 27;
  rtonTableIDs["PresentTableTypes.rton"] = 28;
  rtonTableIDs["PresentTypes.rton"] = 29;
  rtonTableIDs["PlantFamilyTypes.rton"] = 30;
  rtonTableIDs["Quests.rton"] = 31;
  rtonTableIDs["QuestsCategories.rton"] = 32;
  rtonTableIDs["LoadingText.rton"] = 33;
  rtonTableIDs["QuestThemes.rton"] = 34;
  rtonTableIDs["QuestsActive.rton"] = 35;
  rtonTableIDs["DailyQuests.rton"] = 36;
  rtonTableIDs["DailyQuestData.rton"] = 37;
  rtonTableIDs["UIWidgetSheets.rton"] = 38;
  rtonTableIDs["NPCDataSheets.rton"] = 39;
  rtonTableIDs["LevelModules.rton"] = 40;
  rtonTableIDs["HeroTypes.rton"] = 41;
  rtonTableIDs["PowerupTypes.rton"] = 42;
  rtonTableIDs["GameFeatures.rton"] = 43;
  rtonTableIDs["ToolPackets.rton"] = 44;
  rtonTableIDs["StreamingMusic.rton"] = 45;
  rtonTableIDs["Products.rton"] = 46;
  rtonTableIDs["MarketLayout.rton"] = 47;
  rtonTableIDs["MarketSchedule.rton"] = 48;
  rtonTableIDs["RAPSchedule.rton"] = 49;
  rtonTableIDs["DailyQuestSchedule.rton"] = 50;
  rtonTableIDs["PlayerSegments.rton"] = 51;
  rtonTableIDs["BoardGridMaps.rton"] = 52;
  rtonTableIDs["LevelModulesDifficulty.rton"] = 53;
  rtonTableIDs["LevelMutatorModules.rton"] = 54;
  rtonTableIDs["LevelMutatorTables.rton"] = 55;
#endif

  // 在此仿照如上格式再续写所需 RtonTableID
}

/* MeteorFlower：为什么写了这么多版本但很多没找偏移？因为这是历史遗留问题。以前就 9.4 9.6 9.8
这三个版本外国友人找偏移找的最多。所以一开始 RestructedLogic
就写了这三个版本。后来幽幽子找我做高视角（虽然 Edgest 现在是不用我做的 so 了。当年因为到处传搞 so
修改有风险，所以为了保密我让他别写我名字，但实际上如果你能找到老 Edgest
的安装包，那里面还能逆向出来我在里面留的防盗标记。），当年他还没找到外国友人给他整外包 so
修改，用的还是 10.3。就这样 10.3 也成了 RL 的常驻版本之一。但是后来发现 BB2
搞的原始工程能用的东西太少了。虽然 EB 是还留着那堆无效代码，但我做 Lite
的时候就给删了。所以本来是有效偏移最全的那三个版本反而被删光了。后来 EB 自己做新功能的时候（是的，RL
真正的有效代码除了框架已经几乎没有外国友人的代码了。），由于 end(exd) 用的也是 10.3。EB 就在 10.3
上面分析了，所以 10.3 偏移找的最全。但我为什么仍然称 RL 是一个 "multi-version"
的工程。是因为其他工程的偏移基本全是在 main
函数里面写个常量完事了。你要是想给自己版本做适配你就慢慢改去吧。只有 RL
提供了一个最有前景的多版本适配框架（当然现在的 RL 的版本适配框架基本都是我写的。EB
是提出了这个概念，但他写的巨不优雅。）至于 8.7.3 是我自己锁 A
包用的版本。如果您也找了其他版本的偏移，希望您向我们发一下 pr 或者用其他方式告知我们偏移。*/
