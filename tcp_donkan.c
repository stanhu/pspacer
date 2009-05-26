/*
 * Donkan-ryoku TCP
 */

#include <linux/module.h>
#include <net/tcp.h>

#undef DEBUG

struct donkan {
	u8 mode;
#define MODE_RENO   (0)
#define MODE_DONKAN (1)
};

static int rtt_thresh = 1; /* 1 ms */
module_param(rtt_thresh, int, 0644);
MODULE_PARM_DESC(rtt_thresh, "mode switch threshold of rout trip time (ms)");

static void tcp_donkan_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct donkan *ca = inet_csk_ca(sk);

	if (ca->mode == MODE_DONKAN) {
		tp->snd_cwnd = tp->snd_cwnd_clamp;
	} else {
		return tcp_reno_cong_avoid(sk, ack, in_flight);
	}
}

static void tcp_donkan_init(struct sock *sk)
{
	struct donkan *ca = inet_csk_ca(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	u32 rtt;

	rtt = dst_metric(dst, RTAX_RTT);
	if ((rtt >> 3) < rtt_thresh) {
		ca->mode = MODE_DONKAN;
	} else {
		ca->mode = MODE_RENO;
	}
}

#ifdef DEBUG
static void tcp_donkan_state(struct sock *sk, u8 ca_state)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->snd_cwnd = max(tp->snd_cwnd, (__u32)tp->snd_cwnd_clamp);
	printk("tcp_donkan_state: %d cnwd=%d cwnd_clamp=%d ssthresh=%d\n", 
	       ca_state, tp->snd_cwnd, tp->snd_cwnd_clamp, tp->snd_ssthresh);
}
#endif

static struct tcp_congestion_ops tcp_donkan = {
	.init		= tcp_donkan_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_donkan_cong_avoid,
#ifdef DEBUG
	.set_state	= tcp_donkan_state,
#endif
	.owner		= THIS_MODULE,
	.name		= "donkan",
};

static int __init tcp_donkan_register(void)
{
	BUG_ON(sizeof(struct donkan) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_donkan);
}

static void __exit tcp_donkan_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_donkan);
}

module_init(tcp_donkan_register);
module_exit(tcp_donkan_unregister);

MODULE_AUTHOR("Ryousei Takano");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Donkan TCP");
