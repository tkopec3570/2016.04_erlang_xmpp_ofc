%%%-------------------------------------------------------------------
%%% @author tkopec
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 07. May 2016 19:19
%%%-------------------------------------------------------------------
-module(xmpp_ofc_ids_switch).
-behaviour(gen_server).

%% API
-export([start_link/1,
         stop/1,
         handle_message/3]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% includes and definitions
-include_lib("of_protocol/include/of_protocol.hrl").
-include_lib("of_protocol/include/ofp_v4.hrl").
-include("xmpp_ofc_v4.hrl").

-record(state, {datapath_id :: binary()}).

-define(SERVER, ?MODULE).
-define(OF_VER, 4).
-define(FM_TIMEOUT_S(Type), case Type of
                                idle ->
                                    20;
                                hard ->
                                    40
                            end).
-define(FM_INITIAL_COOKIE, <<0, 0, 0, 0, 0, 0, 0, 150>>).
-define(FLOW_STAT_REQUEST_INTERVAL, 5000).
-define(PACKETS_THRESHOLD, 10).
%%%===================================================================
%%% API
%%%===================================================================

-spec(start_link(binary()) ->
    {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link(DatapathId) ->
    {ok, Pid} = gen_server:start_link(?MODULE, [DatapathId], []),
    {ok, Pid, subscriptions(), [init_flow_mod()]}.

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

-spec handle_message(pid(),
                     {MsgType :: term(),
                      Xid :: term(),
                      MsgBody :: [tuple()]},
                     [ofp_message()]) -> [ofp_message()].
handle_message(Pid, Msg, OFMessages) ->
    gen_server:call(Pid, {handle_message, Msg, OFMessages}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([DatapathId]) ->
    {ok, #state{datapath_id = DatapathId}}.

handle_call({handle_message, Msg = {packet_in, _, MsgBody}, CurrOFMessages},
            _From, State = #state{datapath_id = Dpid}) ->
    case packet_in_extract([reason, cookie], MsgBody) of
        [action, ?FM_INITIAL_COOKIE] ->
            {OFMessages} = handle_packet_in(Msg, Dpid),
            {reply, OFMessages ++ CurrOFMessages, State};
        _ ->
            {reply, CurrOFMessages, State}
    end;

handle_call({handle_message, Msg = {flow_stats_reply, _, MsgBody}, CurrOFMessages},
            _From, State = #state{datapath_id = DatapathId}) ->
    case flow_stats_extract(cookie, MsgBody) of
        <<0, 0, 0, 0, 0, 0, 0, 200>> ->
            OFMsg = handle_flow_stats(Msg, DatapathId),
            {reply, OFMsg ++ CurrOFMessages, State};
        _ ->
            {reply, CurrOFMessages, State}
    end.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({send_flow_stats_request, DatapathId, TCPSrc, IpSrc}, State) ->
    Matches = [{eth_type, 16#0800},
               {ipv4_src, IpSrc},
               {ip_proto, <<6>>},
               {tcp_src, TCPSrc},
               {tcp_dst, <<5222:16>>}],
    TableId = 0,
    FlowStats = of_msg_lib:get_flow_statistics(?OF_VER,
                                               TableId,
                                               Matches,
                                               []),
    ofs_handler:send(DatapathId, FlowStats),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

subscriptions() ->
    [packet_in, flow_stats_reply].

init_flow_mod() ->
    Matches = [{eth_type, 16#0800}, {ip_proto, <<6>>}, {tcp_dst, <<5222:16>>}],
    Instructions = [{apply_actions, [{output, controller, no_buffer}]}],
    FlowOpts = [{table_id, 0}, {priority, 150},
                {idle_timeout, 0},
                {idle_timeout, 0},
                {cookie, ?FM_INITIAL_COOKIE},
                {cookie_mask, <<0, 0, 0, 0, 0, 0, 0, 0>>}],
    of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts).

handle_packet_in({_, Xid, PacketIn}, Dpid) ->
    [IpSrc, TCPSrc] = packet_in_extract([ipv4_src, tcp_src], PacketIn),
    Matches = [{eth_type, 16#0800},
               {ipv4_src, IpSrc},
               {ip_proto, <<6>>},
               {tcp_src, TCPSrc},
               {tcp_dst, <<5222:16>>}],
    Instructions = [{apply_actions, [{output, 1, no_buffer}]}],
    FlowOpts = [{table_id, 0}, {priority, 200},
                {idle_timeout, ?FM_TIMEOUT_S(idle)},
                {hard_timeout, ?FM_TIMEOUT_S(hard)},
                {cookie, <<0, 0, 0, 0, 0, 0, 0, 200>>},
                {cookie_mask, <<0, 0, 0, 0, 0, 0, 0, 0>>}],
    FM = of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts),
    PO = packet_out(Xid, PacketIn, 1),
    schedule_flow_stats_request(Dpid, IpSrc, TCPSrc),
    {[FM, PO]}.

drop_flow_mod(IpSrc, TCPSrc) ->
    lager:info("Initializing drop flow mod"),
    Matches = [{eth_type, 16#0800},
               {ipv4_src, IpSrc},
               {ip_proto, <<6>>},
               {tcp_src, TCPSrc},
               {tcp_dst, <<5222:16>>}],
    Instructions = [{apply_actions, []}],
    FlowOpts = [{table_id, 0}, {priority, 250},
                {idle_timeout, ?FM_TIMEOUT_S(idle)},
                {hard_timeout, ?FM_TIMEOUT_S(hard)},
                {cookie, <<0, 0, 0, 0, 0, 0, 0, 250>>},
                {cookie_mask, <<0, 0, 0, 0, 0, 0, 0>>}],
    [of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts)].

handle_flow_stats({_, _, MsgBody}, DatapathId) ->
    case flow_stats_extract(flows, MsgBody) of
        [] ->
            [];
        _ ->
            [IpSrc, TCPSrc, PacketCount, DurationSec] =
            flow_stats_extract([ipv4_src,
                                tcp_src,
                                packet_count,
                                duration_sec], MsgBody),
            case packets_threshold_exceed(PacketCount, DurationSec) of
                true ->
                    drop_flow_mod(IpSrc, TCPSrc);
                false ->
                    schedule_flow_stats_request(DatapathId, IpSrc, TCPSrc),
                    []
            end
    end.

packet_out(Xid, PacketIn, OutPort) ->
    Actions = [{output, OutPort, no_buffer}],
    {InPort, BufferIdOrPacketPortion} =
    case packet_in_extract(buffer_id, PacketIn) of
        no_buffer ->
            list_to_tuple(packet_in_extract([in_port, data],
                                            PacketIn));
        BufferId when is_integer(BufferId) ->
            {packet_in_extract(in_port, PacketIn), BufferId}
    end,
    PacketOut = of_msg_lib:send_packet(?OF_VER,
                                       BufferIdOrPacketPortion,
                                       InPort,
                                       Actions),
    PacketOut#ofp_message{xid = Xid}.

packet_in_extract(Elements, PacketIn) when is_list(Elements) ->
    [packet_in_extract(H, PacketIn) || H <- Elements];
packet_in_extract(src_mac, PacketIn) ->
    <<_:6/bytes, SrcMac:6/bytes, _/binary>> = proplists:get_value(data, PacketIn),
    SrcMac;
packet_in_extract(dst_mac, PacketIn) ->
    <<DstMac:6/bytes, _/binary>> = proplists:get_value(data, PacketIn),
    DstMac;
packet_in_extract(in_port, PacketIn) ->
    <<InPort:32>> = proplists:get_value(in_port, proplists:get_value(match, PacketIn)),
    InPort;
packet_in_extract(ipv4_src, PacketIn) ->
    Data = packet_in_extract(data, PacketIn),
    <<_:26/bytes, IpSrc:4/bytes, _/binary>> = Data,
    IpSrc;
packet_in_extract(tcp_src, PacketIn) ->
    Data = packet_in_extract(data, PacketIn),
    <<_:14/bytes, _:4, IHL:4, _:19/bytes, IpData/binary>> = Data,
    OptionsLength = 4 * (IHL - 5),
    <<_:OptionsLength/bytes, TcpSrc:2/bytes, _/binary>> = IpData,
    TcpSrc;
packet_in_extract(cookie, PacketIn) ->
    proplists:get_value(cookie, PacketIn);
packet_in_extract(buffer_id, PacketIn) ->
    proplists:get_value(buffer_id, PacketIn);
packet_in_extract(data, PacketIn) ->
    proplists:get_value(data, PacketIn);
packet_in_extract(reason, PacketIn) ->
    proplists:get_value(reason, PacketIn).


flow_stats_extract(Elements, FlowStats) when is_list(Elements) ->
    [flow_stats_extract(H, FlowStats) || H <- Elements];
flow_stats_extract(ipv4_src, FlowStats) ->
    proplists:get_value(ipv4_src, flow_stats_extract(match, FlowStats));
flow_stats_extract(tcp_src, FlowStats) ->
    proplists:get_value(tcp_src, flow_stats_extract(match, FlowStats));
flow_stats_extract(packet_count, FlowStats) ->
    proplists:get_value(packet_count, flow_stats_extract(flows, FlowStats));
flow_stats_extract(duration_sec, FlowStats) ->
    proplists:get_value(duration_sec, flow_stats_extract(flows, FlowStats));
flow_stats_extract(flows, FlowStats) ->
    Flows = proplists:get_value(flows, FlowStats),
    case Flows of
        [] -> [];
        List -> hd(List)
    end;
flow_stats_extract(match, FlowStats) ->
    proplists:get_value(match, flow_stats_extract(flows, FlowStats));
flow_stats_extract(cookie, FlowStats) ->
    proplists:get_value(cookie, flow_stats_extract(flows, FlowStats)).

schedule_flow_stats_request(DatapathId, IpSrc, TCPSrc) ->
    timer:send_after(?FLOW_STAT_REQUEST_INTERVAL,
                     {send_flow_stats_request,
                      DatapathId, TCPSrc, IpSrc}).

packets_threshold_exceed(PacketCount, DurationSec) ->
    PacketCount / (DurationSec / 60) > ?PACKETS_THRESHOLD.

