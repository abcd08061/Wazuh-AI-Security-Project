# Wazuh-AI-Security-Project

<img width="516" height="259" alt="螢幕擷取畫面 2026-01-13 154630" src="https://github.com/user-attachments/assets/9ea7cf71-c2bd-42cb-9cc7-eef9c0c701b7" />
<img width="1159" height="1377" alt="螢幕擷取畫面 2026-01-14 150051" src="https://github.com/user-attachments/assets/9d947091-fbe1-4926-83a9-b1de833a8b04" />

 網路安全與加密流量分析實驗報告
 第一部分：pfSense 防火牆與 Wazuh SIEM 連動實作
 1. 實作目標
    配置 pfSense 防火牆透過 Syslog 將安全日誌傳送至 Wazuh 監控平台，實現日誌集中化管理。
 2. 關鍵配置
    步驟pfSense 端：
      進入 Status > System Logs > Settings。
      啟用 Remote Logging 並設定目標伺服器為 192.168.130.128:514。
      暫時關閉防火牆過濾規則以確保管理介面連線：使用指令 pfctl -d。
    Wazuh 端：
      修改 /var/ossec/etc/ossec.conf，新增 <remote> 區塊以接收 UDP 514 埠的 Syslog 資料。
      重啟 Wazuh 服務：sudo systemctl restart wazuh-manager。
3. 實作成果
     在 Wazuh Dashboard 的 Discover 介面中，成功搜尋到來自 pfSense (192.168.130.129) 的日誌紀錄

第二部分：加密流量分析研究 (ET-BERT vs. LLM)
1. 研究摘要本作業針對加密流量分析方法進行概念性比較，說明 ET-BERT 與 LLM 在不同加密流量場景（如合法遠端、惡意行為）下的適用性與限制。本研究使用既有 ET-BERT 預訓練模型之概念進行推論評估，未進行實際模型大規模訓練。
2. 技術架構分析流程如下：PCAP 封包截取 ➔ 特徵提取 (5-tuple, packet size, time) ➔ 模型推論 (ET-BERT / LLM) ➔ 分類與解釋
3. ET-BERT 與 LLM 核心對比表透過下表說明傳統加密流量模型與大型語言模型在資安偵測上的差異：
   <img width="721" height="299" alt="螢幕擷取畫面 2026-01-14 161355" src="https://github.com/user-attachments/assets/93eb5289-b47d-49f8-a12f-928913962582" />
4. LLM 結構化特徵分析範例
   將加密流量特徵轉換為 JSON 格式，提供給 LLM 進行推理分析：
   {
    "avg_packet_size": 512,
    "std_packet_size": 20,
    "inter_arrival_time_ms": 60000,
    "flow_duration_sec": 1800,
    "direction": "mostly_outbound"
   }
以上特徵可協助 LLM 判斷該流量是否具備 Beaconing 行為（如 Cobalt Strike）或長連線特徵（如 TeamViewer）。
