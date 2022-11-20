/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP forwarding functionality.
 *
 * Authors:	see ip.c
 *
 * Fixes:
 *		Many		:	Split from ip.c , see ip_input.c for
 *					history.
 *		Dave Gregorich	:	NULL ip_rt_put fix for multicast
 *					routing.
 *		Jos Vos		:	Add call_out_firewall before sending,
 *					use output device for accounting.
 *		Jos Vos		:	Call forward firewall after routing
 *					(always use output device).
 *		Mike McLagan	:	Routing by source
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>

/**
 * 进行转发处理的相关的函数。
 *
 * dst_input(local/forward)
 * ip_forward
 * │
 * └──►NF_INET_FORWARD
 *     ▼
 *     ip_forward_finish
 *     │
 *     └──►ip_forward_options
 *         ▼
 *         dst_output(ip_output/ip_mc_output)
 */

/**
 * 完成转发选项处理，并调用将数据包输出到网络设备的接口函数。
 */
static int ip_forward_finish(struct sk_buff *skb)
{
	struct ip_options * opt	= &(IPCB(skb)->opt);

	IP_INC_STATS_BH(dev_net(skb_dst(skb)->dev), IPSTATS_MIB_OUTFORWDATAGRAMS);

	/* 处理转发IP选项，包括记录路由选项和时间戳选项。*/
	if (unlikely(opt->optlen))
		ip_forward_options(skb);

	/* 根据路由查找的结果，调用单播输出的ip_output，或者组播的ip_mc_output */
	return dst_output(skb);
}

/**
 * 查找路由结果后，进行转发操作的处理函数。
 * 	"NF_INET_FORWARD"
 * 	ip_forward_finish
 */
int ip_forward(struct sk_buff *skb)
{
	struct iphdr *iph;	/* Our header */
	struct rtable *rt;	/* Route we use */
	struct ip_options * opt	= &(IPCB(skb)->opt);

	if (skb_warn_if_lro(skb))
		goto drop;

	/* 查找 IPsec 策略数据库。如果查找失败, 则丢弃该数据报。
	 */
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb))
		goto drop;

	/* 如果数据报中存在路由警告选项，则调用 ip_call_ra_chain 将数据报输入给
	 * 对路由警告选项感兴趣的用户进程。如果成功，则不再转发数据报。
	 */
	if (IPCB(skb)->opt.router_alert && ip_call_ra_chain(skb))
		return NET_RX_SUCCESS;

	/* 与ip_rcv中的检查一样，即使是需要进行转发的数据包，收到时的MAC地址也
	 * 应该是当前主机地址。
	 */
	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	/* include/linux/skbuff.h:2205
	 * 由于在转发过程中可能会修改IP首部，因此将ip_summed 设置为CHECKSUM_NONE，
	 * 在后续的输出时还得由软件来执行校验和。
	 */
	skb_forward_csum(skb);

	/*
	 *	According to the RFC, we must first decrease the TTL field. If
	 *	that reaches zero, we must reply an ICMP control message telling
	 *	that the packet's lifetime expired.
	 * 进行转发时，需要将 TTL字段减一，若已经小于等于1，就应该丢弃该数据包，
	 * 并发送超时 ICMP 到发送方。
	 */
	if (ip_hdr(skb)->ttl <= 1)
		goto too_many_hops;

	/* 进行 IPsec 路由选路和转发处理，如果失败，则丢弃该数据报。*/
	if (!xfrm4_route_forward(skb))
		goto drop;

	rt = skb_rtable(skb);

	/* 如果数据报启用严格源路由选项，且数据报的下一跳不是网关，则发送
	 * 目的不可达 ICMP 报文到发送方，并丢弃该数据报。
	 */
	if (opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto sr_failed;

	if (unlikely(skb->len > dst_mtu(&rt->dst) && !skb_is_gso(skb) &&
		     (ip_hdr(skb)->frag_off & htons(IP_DF))) && !skb->local_df) {
		IP_INC_STATS(dev_net(rt->dst.dev), IPSTATS_MIB_FRAGFAILS);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(dst_mtu(&rt->dst)));
		goto drop;
	}

	/* We are about to mangle packet. Copy it!
	 * 后续操作需要修改header，先检查一下skb中前面的空闲空间是否能满足需求，
	 * 不能满足就需要重新分配。
	 */
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->dst.dev)+rt->dst.header_len))
		goto drop;
	iph = ip_hdr(skb);

	/* Decrease ttl after skb cow done */
	ip_decrease_ttl(iph);

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */
	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr && !skb_sec_path(skb))
		ip_rt_send_redirect(skb);

	skb->priority = rt_tos2priority(iph->tos);

	/* 经过netfilter的NF_INET_FORWARD，调用ip_forward_finish
	 */
	return NF_HOOK(NFPROTO_IPV4, NF_INET_FORWARD, skb, skb->dev,
		       rt->dst.dev, ip_forward_finish);

sr_failed:
	/*
	 *	Strict routing permits no gatewaying
	 */
	 icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
	 goto drop;

too_many_hops:
	/* Tell the sender its packet died... */
	IP_INC_STATS_BH(dev_net(skb_dst(skb)->dev), IPSTATS_MIB_INHDRERRORS);
	icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
