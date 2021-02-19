import json
import click
import requests
from pyln.proto.primitives import ShortChannelId
import logging

logging.basicConfig(format='%(asctime)-15s %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def lookup_tx(txid):
    logger.debug(f"Retrieving metadata for tx {txid}")
    meta = requests.get(
        f'https://blockstream.info/api/tx/{txid}'
    ).json()

    logger.debug(f"Retrieving spending information for {len(meta['vout'])} outputs")
    spends = requests.get(
        f'https://blockstream.info/api/tx/{txid}/outspends'
    ).json()

    for out, spend in zip(meta['vout'], spends):
        out['spent_by'] = spend

    return meta


def resolve_scid(scid):
    logger.debug(f"Resolving blockhash for height {scid.block}")
    block_hash = requests.get(
        f'https://blockstream.info/api/block-height/{scid.block}'
    ).content.decode('ASCII')
    logger.debug(f"Blockheight {scid.block} resolved to {block_hash}")
    block_txs = requests.get(
        f'https://blockstream.info/api/block/{block_hash}/txids'
    ).json()
    txid = block_txs[scid.txnum]
    logger.debug(f"Resolved {scid} to {txid}:{scid.outnum}")
    return (txid, scid.outnum)


@click.group()
def cli():
    """A tool to inspect Lightning Network metadata.
    """
    pass


@cli.group()
def channels():
    """Commands related to channel operations and data lookup.
    """
    pass


@channels.command()
@click.argument("short_channel_id", type=str, required=True)
def analyze(short_channel_id):
    """Given a short-channel-id we go and check its status and eventual close.

    The funding_tx is resolved from the short-channel-id and its
    contents are displayed as 'funding_tx', then we go and check if
    the funding output is still unspent, in which case the channel is
    still open. If the channel is no longer open we proceed to check
    the close transaction. We can determine its type (collaborative or
    unilateral) depending on the output types. We then also look at
    the to_local output to determine if it was swept (correct close)
    or if it was penalized (the closer attempted to cheat).

    This command currently does not look up HTLCs, but that can be
    added in future.

    """
    scid = ShortChannelId.from_str(short_channel_id)
    txid, outnum = resolve_scid(scid)
    funding_tx = lookup_tx(txid)

    funding_output = funding_tx['vout'][scid.outnum]
    spender = funding_output['spent_by']
    penalty = False
    lifetime = None

    if spender['spent']:
        logger.debug(f"Funding output was spent, looking up closing tx")
        close_txid = spender['txid']
        close_tx = lookup_tx(close_txid)

        # Now look at the close tx, and determine what type of close it is.
        out_types = [o['scriptpubkey_type'] for o in close_tx['vout']]

        if 'v0_p2wsh' in out_types:
            close_type = 'unilateral'
        else:
            close_type = 'collaborative'

        lifetime = spender['status']['block_height'] - scid.block

        logger.debug(f"Close determined to be {close_type}")

        # And finally look at the spender of the deferred output to
        # see if it is going to be penalized (branch 1 in the if-else
        # script) or whether the timeout expires and the closing party
        # gets its funds back.
        for i, out in enumerate(close_tx['vout']):
            if out['scriptpubkey_type'] != 'v0_p2wsh':
                # This is the direct return to closee output, no need
                # to follow that
                out['type'] = 'direct_to_closee'
                continue

            if not out['spent_by']['spent']:
                # No point in following this link, the output isn't
                # spent yet, so we can't determine its type.
                out['type'] = 'unknown'
                continue

            return_tx = lookup_tx(out['spent_by']['txid'])

            # Determine which input is the spending one:
            return_index = None
            return_in = None
            for i, inp in enumerate(return_tx['vin']):
                if inp['txid'] == close_tx['txid']:
                    return_index = i
                    return_in = inp
                    break
            assert(return_index is not None)
            assert(return_in is not None)

            # The type is defined by the argument passed to OP_IF in
            # the second position of the to_local output. This is
            # either 0x00 (or empty string) for a sweep, and 0x01 for
            # a penalty.
            return_in = return_tx['vin'][0]
            if return_in['witness'][1] == '01':
                return_type = 'penalty'
                penalty = True
            else:
                return_type = 'sweep'

            out['type'] = return_type
    else:
        close_tx = None
        close_type = None

    print(json.dumps({
        "funding_tx": funding_tx,
        "close_tx": close_tx,
        "status": 'open' if close_tx is None else 'closed',
        'lifetime': lifetime,
        "close_type": close_type,
        'penalty': penalty,
    }, indent=2))


if __name__ == "__main__":
    cli()
