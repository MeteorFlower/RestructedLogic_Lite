#ifndef __aarch64__

#error "This sub-project is only for ARM64 architecture."

#endif

constexpr size_t UNKNOWN = 0;
#define GAME_VERSION 873
// 填入版本号，为去掉小数点的版本号
// UNKNOWN 表示暂时未知

#if GAME_VERSION == 873

// ==== MaxZoom ====
constexpr size_t BoardZoomAddr = 0xA331D4;                 // 高视角缩放
constexpr size_t BoardZoom2Addr = 0xA33434;                // 高视角缩放 2
constexpr size_t LawnAppScreenWidthHeightAddr = 0x8DDA28;  // 分辨率设置

// ==== AliasToID ====
constexpr size_t PlantNameMapperAddr = UNKNOWN;  // 植物名映射（10.3 起不需要）
constexpr int firstFreePlantID = UNKNOWN;        // 自定义植物 ID 起始值

// ==== CDNExpansion ====
constexpr size_t CDNLoadAddr = UNKNOWN;  // RTON 加载（名字 + 表 ID + 标志）

// ==== LogOutput ====
// 无后缀那个是变参 printf 形（cpp 里已实现），下面三个是本版其它日志输出入口（待适配）
constexpr size_t LogOutputFuncAddr = 0x13B4F60;
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
constexpr size_t ResourceManagerFuncAddr = 0x8E6CB0;  // 资源管理器

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = 0x8E6420;  // 暂停菜单显示

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = 0x7D58E0;  // 图鉴状态更新
constexpr size_t NarrativeCheckAddr = 0x1311080;     // 剧情检查
constexpr size_t TutorialCheckAddr = 0x1311FC4;      // 教程检查

// ==== GeneralFunction（通用工具：弱指针/类型系统/实体动画）====
constexpr size_t AnimRigGetAddr = 0xBE0878;           // 实体+104 弱指针取 AnimRig
constexpr size_t DirGetAddr = 0x15021C8;              // 类型目录
constexpr size_t DirRegisterHandlerAddr = 0x15085C8;  // 目录槽5: 注册类型处理
constexpr size_t RegisterClassAddr = 0x1518CAC;       // 注册类型
constexpr size_t RegistryGetAddr = 0x15020B0;         // RtClass 注册表单例
constexpr size_t RtClassContextAddr = 0x13CA2C0;      // 取 RtClass 上下文
constexpr size_t RtClassCtorAddr = 0x15180F4;         // RtClass 构造（new 0x48 + 注册）
constexpr size_t RtWeakPtrBindAddr = 0x13D2EFC;       // RtWeakPtr 绑定
constexpr size_t RtWeakPtrCopyAddr = 0x13B8750;       // RtWeakPtr 拷贝
constexpr size_t RtWeakPtrCtorAddr = 0x13B8620;       // RtWeakPtr 构造（置0）
constexpr size_t RtWeakPtrDtorAddr = 0x13B8698;       // RtWeakPtr 析构
constexpr size_t RtWeakPtrGetAddr = 0x13CD330;        // RtWeakPtr 取对象
constexpr size_t RtWeakPtrHandleAddr = 0x13B86BC;     // RtWeakPtr 取句柄
constexpr size_t RtWeakPtrResolveAddr = 0x13D26D4;    // RtWeakPtr 句柄解析
constexpr size_t RtWeakPtrValidAddr = 0x13B87B0;      // RtWeakPtr 有效检查
constexpr size_t SexyStringAssignAddr = 0x56CFA0;     // SexyString 赋值（dst, 字符数据, 长度）
constexpr size_t ZombieAnimRigGetAddr = 0x68A8A8;     // 僵尸+1056 弱指针取 AnimRig

// ==== SnapdragonWarming ====
constexpr size_t PowerListFindAddr = 0xC2C43C;       // 列表按(type,sub)找 power
constexpr size_t PropsContextAddr = 0xB1FBF0;        // 取 props+72 powers 上下文
constexpr size_t PropsPowersBindAddr = 0x116AD88;    // 绑定 props+272 powers 列表
constexpr size_t SnapdragonInitAddr = 0xE024A8;      // Snapdragon init（hook 点）
constexpr size_t WarmingCompFactoryAddr = 0xDC8A6C;  // 温暖组件附加工厂（类型63）
constexpr size_t WarmingSetPropsAddr = 0x727C44;     // 温暖 SetProps（拷贝配置到组件+376）

// ==== AshDeathrattleFix ====
constexpr size_t BullVeteranVtableAddr = 0x21CA418;       // ZombieBullVeteran vtable——patch 槽183
constexpr size_t BullVtableAddr = 0x21C9CC8;              // ZombieBull vtable——patch 槽183
constexpr size_t DinoBullyVeteranVtableAddr = 0x21D3268;  // DinoBullyVeteran vtable——patch 槽183
constexpr size_t GargantuarDeathAddr = 0xAE59DC;          // 巨人族槽183 死亡收尾
constexpr size_t ZCorpImpVtableAddr = 0x21FF4A8;          // ZombieZCorpImp vtable——patch 槽183
constexpr size_t ZombieAnimPauseAddr = 0x978918;          // 动画对象+179 = mPaused

// ==== SpringBeanPFInvuln ====
// 槽 81 实现仅 12 字节，代码 hook 会越界覆盖邻槽函数，故改为 patchVFTable 替换（代码区零改动）
constexpr size_t IsPlantFoodActiveAddr = 0x116D9C0;  // PF 状态查询（+256 || 实体槽86，官方检查）
constexpr size_t SpringBeanDieAddr = 0xE09030;       // vtable 槽 81 原函数（死亡回调）
constexpr size_t SpringBeanVtableAddr = 0x2240408;   // SpringBean vtable 起点（off_2240408）
constexpr int kSpringBeanDieSlot = 81;               // 死亡回调槽位

// ==== CostumeSkinPort（高版本 skin 装扮搬运）====
// 只对 9.x 之前的版本有意义（高版本游戏自带），其余版本块里没有本段
// 方案：不改 CostumeItemType 布局（元素是 vector 内联 88B，stride/魔数无法 patch），skin
// 标记直接写在 原有的 LayerName 字段里：值以 "skin:" 开头，冒号后是 PopAnimName。
constexpr size_t CostumeFindItemAddr = 0x137FFE8;    // 按 CostumeID 查 item（stride 88）
constexpr size_t CostumeGetIdAddr = 0x138061C;       // 取当前 CostumeID（参数 = 植物类型名字符串）
constexpr size_t CostumeAnimRateGetAddr = 0x973D84;  // 动画速率读取（obj+32 读到 +40 float）
constexpr size_t CostumeAnimRateSetAddr = 0x973D90;  // 动画速率写入
constexpr size_t HotUIPlantAnimAddr = 0x115AE70;     // 商店 HotUI 植物动画（按名字建动画的预览）
constexpr uint64_t kHotUiPlantNameOff = 656;         // 控件上的植物名（查注册表用）
constexpr uint64_t kHotUiLayerNameOff = 680;         // 装扮 LayerName（判定 skin 用）
constexpr size_t PlantRegistryGlobalAddr = 0x234DAF8;  // 植物类型注册表单例（指针）
constexpr size_t PlantRegistryFindAddr = 0x573D24;     // 注册表按名字查找（返回节点）
constexpr size_t CostumePreviewCtorAddr = 0x8AB644;    // 图鉴/选卡卡片初始化（之后按植物覆盖 box）
constexpr size_t CostumeAnimApplierAddr = 0xBE7F74;    // 动画创建 hook 点（名字解析后创建）
constexpr size_t CostumeSwitchAddr = 0x8AC664;         // 图鉴切换装扮入口（切换后重建动画）

#endif

#if GAME_VERSION == 941

// ==== MaxZoom ====
constexpr size_t BoardZoomAddr = UNKNOWN;
constexpr size_t BoardZoom2Addr = UNKNOWN;
constexpr size_t LawnAppScreenWidthHeightAddr = UNKNOWN;

// ==== AliasToID ====
constexpr size_t PlantNameMapperAddr = UNKNOWN;
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
constexpr size_t WorldMapDoMovementAddr = UNKNOWN;

// ==== HookResourceManagerFunc ====
constexpr size_t ResourceManagerFuncAddr = UNKNOWN;

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = UNKNOWN;

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = UNKNOWN;
constexpr size_t NarrativeCheckAddr = UNKNOWN;
constexpr size_t TutorialCheckAddr = UNKNOWN;

// ==== GeneralFunction ====
constexpr size_t AnimRigGetAddr = UNKNOWN;
constexpr size_t DirGetAddr = UNKNOWN;
constexpr size_t DirRegisterHandlerAddr = UNKNOWN;
constexpr size_t RegisterClassAddr = UNKNOWN;
constexpr size_t RegistryGetAddr = UNKNOWN;
constexpr size_t RtClassContextAddr = UNKNOWN;
constexpr size_t RtClassCtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrBindAddr = UNKNOWN;
constexpr size_t RtWeakPtrCopyAddr = UNKNOWN;
constexpr size_t RtWeakPtrCtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrDtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrGetAddr = UNKNOWN;
constexpr size_t RtWeakPtrHandleAddr = UNKNOWN;
constexpr size_t RtWeakPtrResolveAddr = UNKNOWN;
constexpr size_t RtWeakPtrValidAddr = UNKNOWN;
constexpr size_t SexyStringAssignAddr = UNKNOWN;
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
constexpr size_t PlantNameMapperAddr = UNKNOWN;
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
constexpr size_t WorldMapDoMovementAddr = UNKNOWN;

// ==== HookResourceManagerFunc ====
constexpr size_t ResourceManagerFuncAddr = UNKNOWN;

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = UNKNOWN;

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = UNKNOWN;
constexpr size_t NarrativeCheckAddr = UNKNOWN;
constexpr size_t TutorialCheckAddr = UNKNOWN;

// ==== GeneralFunction ====
constexpr size_t AnimRigGetAddr = UNKNOWN;
constexpr size_t DirGetAddr = UNKNOWN;
constexpr size_t DirRegisterHandlerAddr = UNKNOWN;
constexpr size_t RegisterClassAddr = UNKNOWN;
constexpr size_t RegistryGetAddr = UNKNOWN;
constexpr size_t RtClassContextAddr = UNKNOWN;
constexpr size_t RtClassCtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrBindAddr = UNKNOWN;
constexpr size_t RtWeakPtrCopyAddr = UNKNOWN;
constexpr size_t RtWeakPtrCtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrDtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrGetAddr = UNKNOWN;
constexpr size_t RtWeakPtrHandleAddr = UNKNOWN;
constexpr size_t RtWeakPtrResolveAddr = UNKNOWN;
constexpr size_t RtWeakPtrValidAddr = UNKNOWN;
constexpr size_t SexyStringAssignAddr = UNKNOWN;
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
constexpr size_t PlantNameMapperAddr = UNKNOWN;
constexpr int firstFreePlantID = 191;

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
constexpr size_t WorldMapDoMovementAddr = UNKNOWN;

// ==== HookResourceManagerFunc ====
constexpr size_t ResourceManagerFuncAddr = UNKNOWN;

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = UNKNOWN;

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = UNKNOWN;
constexpr size_t NarrativeCheckAddr = UNKNOWN;
constexpr size_t TutorialCheckAddr = UNKNOWN;

// ==== GeneralFunction ====
constexpr size_t AnimRigGetAddr = UNKNOWN;
constexpr size_t DirGetAddr = UNKNOWN;
constexpr size_t DirRegisterHandlerAddr = UNKNOWN;
constexpr size_t RegisterClassAddr = UNKNOWN;
constexpr size_t RegistryGetAddr = UNKNOWN;
constexpr size_t RtClassContextAddr = UNKNOWN;
constexpr size_t RtClassCtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrBindAddr = UNKNOWN;
constexpr size_t RtWeakPtrCopyAddr = UNKNOWN;
constexpr size_t RtWeakPtrCtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrDtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrGetAddr = UNKNOWN;
constexpr size_t RtWeakPtrHandleAddr = UNKNOWN;
constexpr size_t RtWeakPtrResolveAddr = UNKNOWN;
constexpr size_t RtWeakPtrValidAddr = UNKNOWN;
constexpr size_t SexyStringAssignAddr = UNKNOWN;
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
constexpr size_t BoardZoomAddr = 0xB380D8;
constexpr size_t BoardZoom2Addr = 0xB3832C;
constexpr size_t LawnAppScreenWidthHeightAddr = 0x9B7800;

// ==== AliasToID ====
constexpr size_t PlantNameMapperAddr = UNKNOWN;
constexpr int firstFreePlantID = UNKNOWN;  // 高版本不需要

// ==== CDNExpansion ====
constexpr size_t CDNLoadAddr = UNKNOWN;

// ==== LogOutput ====
constexpr size_t LogOutputFuncAddr = 0x15EDE68;
constexpr size_t LogOutputFuncAddr_Simple = UNKNOWN;
constexpr size_t LogOutputFuncAddr_Struct = UNKNOWN;
constexpr size_t LogOutputFuncAddr_v2 = UNKNOWN;

// ==== PrimeGlyphCacheLimitation ====
constexpr size_t PrimeGlyphCacheAddr = 0x18A5400;

// ==== RSBDecrypt ====
constexpr size_t RSBPathRecorderAddr = 0x177F714;

// ==== WorldMapVerticalScrolling ====
constexpr size_t WorldMapScrollAddr = 0x820CD4;
constexpr size_t KeepCenterAddr = 0x826944;
constexpr size_t ScrollInertanceAddr = 0x830194;

// ==== HookResourceManagerFunc ====
constexpr size_t ResourceManagerFuncAddr = 0x9C0F70;

// ==== EnableDangerRoomRestart ====
constexpr size_t PauseMenuShowAddr = UNKNOWN;

// ==== DisableAlmanacTutorial ====
constexpr size_t AlmanacStateUpdateAddr = UNKNOWN;
constexpr size_t NarrativeCheckAddr = UNKNOWN;
constexpr size_t TutorialCheckAddr = UNKNOWN;

// ==== GeneralFunction ====
constexpr size_t AnimRigGetAddr = UNKNOWN;
constexpr size_t DirGetAddr = UNKNOWN;
constexpr size_t DirRegisterHandlerAddr = UNKNOWN;
constexpr size_t RegisterClassAddr = UNKNOWN;
constexpr size_t RegistryGetAddr = UNKNOWN;
constexpr size_t RtClassContextAddr = UNKNOWN;
constexpr size_t RtClassCtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrBindAddr = UNKNOWN;
constexpr size_t RtWeakPtrCopyAddr = UNKNOWN;
constexpr size_t RtWeakPtrCtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrDtorAddr = UNKNOWN;
constexpr size_t RtWeakPtrGetAddr = UNKNOWN;
constexpr size_t RtWeakPtrHandleAddr = UNKNOWN;
constexpr size_t RtWeakPtrResolveAddr = UNKNOWN;
constexpr size_t RtWeakPtrValidAddr = UNKNOWN;
constexpr size_t SexyStringAssignAddr = UNKNOWN;
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
