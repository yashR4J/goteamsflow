

# def plot_bandwidth(df, limit=10):
#     bandwidth_data = df[(df["Bandwidth"] > 0) & (~df["Source IP"].apply(is_ip_in_teams_ranges))].copy()
#     if bandwidth_data.empty:
#         print("No data found")
#         return

#     plt.figure(figsize=(12, 6))

#     bandwidth_data.loc[:, "Bandwidth (Mbps)"] = bandwidth_data["Bandwidth"] / 1e6  # Convert to Mbps for readability

#     unique_ips = bandwidth_data["Source IP"].unique()
#     limited_ips = unique_ips[:limit]

#     sns.lineplot(x="Timestamp", y="Bandwidth (Mbps)", data=bandwidth_data[bandwidth_data["Source IP"].isin(limited_ips)], hue="Source IP", palette="tab10", alpha=0.6)
    
#     plt.title("Bandwidth over Time")
#     plt.xlabel("Timestamp")
#     plt.ylabel("Bandwidth (bps)")
#     plt.grid(True, linestyle="--", linewidth=0.5, alpha=0.7)
#     plt.xticks(rotation=45, ha="right")
#     plt.tight_layout()
#     plt.savefig("bandwidth_over_time.png")
#     plt.close()

#     return generate_bandwidth_metrics_summary(bandwidth_data)

# def plot_ice_renegotiations(df):
#     """
#     Plots the ICE renegotiation attempts per session over time with integer y-axis ticks.
#     """
#     session_establishments = df[(df['Type'] == 'Session Setup') & (df['State'] == 'Established') & (df['Session Setup Type'] == 'Initial Setup')].copy()
#     if session_establishments.empty:
#         print("No data found")
#         return

#     timestamps = session_establishments['Timestamp']
#     renegotiation_counts = session_establishments['Renegotiation Attempts']
    
#     plt.figure(figsize=(12, 6))
#     sns.lineplot(x=timestamps, y=renegotiation_counts, marker="o", alpha=0.6)
    
#     plt.title("ICE Renegotiation Attempts Over Time")
#     plt.xlabel("Timestamp")
#     plt.ylabel("Renegotiation Attempts")
#     plt.grid(True, linestyle="--", linewidth=0.5, alpha=0.7)
#     plt.xticks(rotation=45, ha="right")

#     ax = plt.gca()
#     ax.yaxis.set_major_locator(MaxNLocator(integer=True))
#     ax.set_ylim(0, max(renegotiation_counts) + 1) 

#     plt.tight_layout()
#     plt.savefig("ice_renegotiation_attempts.png")
#     plt.close()
    
#     return generate_renegotiation_attempts_summary(session_establishments)

# @quant_summary("RTP Jitter Metrics Summary")
# def generate_jitter_metrics_summary(rtp_packets):
#     overall_summary = {
#         "Mean Jitter (ms)": rtp_packets["Jitter"].mean(),
#         "Median Jitter (ms)": rtp_packets["Jitter"].median(),
#         "Max Jitter (ms)": rtp_packets["Jitter"].max(),
#         "Standard Deviation Jitter (ms)": rtp_packets["Jitter"].std(),
#         "90th Percentile Jitter (ms)": rtp_packets["Jitter"].quantile(0.9),
#         "95th Percentile Jitter (ms)": rtp_packets["Jitter"].quantile(0.95)
#     }
    
#     print("Overall Jitter Metrics Summary:")
#     for metric, value in overall_summary.items():
#         print(f"{metric}: {value:.2f}")

#     media_types = ["Audio", "Video", "ScreenShare"]
#     media_summaries = {}
    
#     for media_type in media_types:
#         media_packets = rtp_packets[rtp_packets["Media Type"].str.contains(media_type, case=False, na=False)]
#         if not media_packets.empty:
#             media_summary = {
#                 "Mean Jitter (ms)": media_packets["Jitter"].mean(),
#                 "Median Jitter (ms)": media_packets["Jitter"].median(),
#                 "Max Jitter (ms)": media_packets["Jitter"].max(),
#                 "Standard Deviation Jitter (ms)": media_packets["Jitter"].std(),
#                 "90th Percentile Jitter (ms)": media_packets["Jitter"].quantile(0.9),
#                 "95th Percentile Jitter (ms)": media_packets["Jitter"].quantile(0.95)
#             }
#             media_summaries[media_type] = media_summary
#             print(f"\n{media_type} Jitter Metrics Summary:")
#             for metric, value in media_summary.items():
#                 print(f"{metric}: {value:.2f}")
    
#     return {"Overall": overall_summary, "ByMediaType": media_summaries}

# @quant_summary("Latency Metrics Summary")
# def generate_latency_metrics_summary(tcp_packets):
#     summary = {
#         "Mean Latency (ms)": tcp_packets["Latency"].mean(),
#         "Median Latency (ms)": tcp_packets["Latency"].median(),
#         "Max Latency (ms)": tcp_packets["Latency"].max(),
#         "Standard Deviation Latency (ms)": tcp_packets["Latency"].std(),
#         "90th Percentile Latency (ms)": tcp_packets["Latency"].quantile(0.9),
#         "95th Percentile Latency (ms)": tcp_packets["Latency"].quantile(0.95)
#     }
#     for metric, value in summary.items():
#         print(f"{metric}: {value:.2f}")
#     return summary


# def plot_rtp_jitter(df):
#     rtp_packets = df[(df["Type"].str.startswith("RTP")) & (df["Jitter"] >= 0)]
#     if rtp_packets.empty:
#         print("No data found")
#         return

#     jitter_mean = rtp_packets["Jitter"].mean()
#     jitter_std = rtp_packets["Jitter"].std()
#     threshold = jitter_mean + 3 * jitter_std  
#     rtp_packets_filtered = rtp_packets[rtp_packets["Jitter"] <= threshold]

#     media_types = ["Audio", "Video", "ScreenShare"]
#     colors = {"Audio": "dodgerblue", "Video": "green", "ScreenShare": "orange"}

#     fig, ax = plt.subplots(figsize=(14, 7))

#     for media_type in media_types:
#         media_packets = rtp_packets_filtered[rtp_packets_filtered["Media Type"].str.contains(media_type, case=False, na=False)]
#         if not media_packets.empty:
#             ax.plot(
#                 media_packets["Timestamp"], media_packets["Jitter"], 
#                 color=colors[media_type], label=media_type, linestyle='-', marker='o', markersize=1.5, alpha=0.8
#             )

#     ax.set_title("RTP Jitter over Time by Media Type", fontsize=14)
#     ax.set_xlabel("Timestamp", fontsize=12)
#     ax.set_ylabel("Jitter (ms)", fontsize=12)
    
#     ax.xaxis.set_major_formatter(mdates.DateFormatter("%I:%M %p"))
#     plt.xticks(rotation=45, ha="right")
    
#     ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.7)
#     ax.spines['top'].set_visible(False)
#     ax.spines['right'].set_visible(False)

#     ax.legend(title="Media Type", loc="upper right", fontsize=10)
#     plt.tight_layout()
#     plt.savefig(args.output or "rtp_jitter_over_time.png")
#     plt.close()

#     return generate_jitter_metrics_summary(rtp_packets_filtered)

# def plot_latency(df):
#     """
#     Plots latency over time for TCP packets, focusing on incoming packets from Teams servers.
#     """
    
#     tcp_packets = df[(df["Type"].str.endswith(" TCP")) & (df["Latency"].notnull()) & (df["Latency"] > 0) & (df["Source IP"].apply(is_ip_in_teams_ranges))]
#     if tcp_packets.empty:
#         print("No data found")
#         return

#     tcp_packets = tcp_packets.sort_values("Timestamp")
#     latency_mean = tcp_packets["Latency"].mean()
#     latency_std = tcp_packets["Latency"].std()
#     threshold = latency_mean + 3 * latency_std  
#     tcp_packets_filtered = tcp_packets[tcp_packets["Latency"] <= threshold]

#     fig, ax = plt.subplots(figsize=(14, 7))

#     ax.plot(
#         tcp_packets_filtered["Timestamp"], tcp_packets_filtered["Latency"],
#         color="steelblue", label="Latency", linestyle='-', marker='o', markersize=1.5, alpha=0.8
#     )

#     rolling_avg_window = 5
#     tcp_packets_filtered["Rolling Average Latency"] = tcp_packets_filtered["Latency"].rolling(window=rolling_avg_window, min_periods=1).mean()
#     ax.plot(
#         tcp_packets_filtered["Timestamp"], tcp_packets_filtered["Rolling Average Latency"],
#         color="darkorange", linestyle="--", label=f"{rolling_avg_window}-Interval Rolling Average"
#     )

#     ax.set_title("TCP Latency over Time", fontsize=14)
#     ax.set_xlabel("Timestamp", fontsize=12)
#     ax.set_ylabel("Latency (ms)", fontsize=12)
    
#     ax.xaxis.set_major_formatter(mdates.DateFormatter("%I:%M %p"))
#     plt.xticks(rotation=45, ha="right")
    
#     ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.7)
#     ax.spines['top'].set_visible(False)
#     ax.spines['right'].set_visible(False)

#     ax.legend(title="Latency Metrics", loc="upper right", fontsize=10)
#     plt.tight_layout()
#     plt.savefig("rtt_over_time.png")
#     plt.close()