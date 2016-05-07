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

-type fwd_table() :: #{MacAddr :: string() => SwitchPort :: integer()}.
-record(state, {datapath_id :: binary(),
                fwd_table :: fwd_table()}).

-define(SERVER, ?MODULE).
-define(OF_VER, 4).
-define(FM_TIMEOUT_S(Type), case Type of
                                idle ->
                                    10;
                                hard ->
                                    30
                            end).
-define(FM_INITIAL_COOKIE, <<0, 0, 0, 0, 0, 0, 0, 150>>).
-define(FLOW_STAT_REQUEST_INTERVAL, 5000).
-define(PACKETS_THRESHOLD, 50).
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
    {ok, #state{datapath_id = DatapathId, fwd_table = #{}}}.

handle_call({handle_message, Msg = {packet_it, _, MsgBody}, CurrOFMessages},
            _From, State = #state{datapath_id = Dpid, fwd_table = FwdTable0}) ->
    case packet_in_extract([reason, cookie], MsgBody) of
        [action, ?FM_INITIAL_COOKIE] ->
            {OFMessages, FwdTable1} = handle_packet_in(Msg, Dpid, FwdTable0),
            {reply, OFMessages ++ CurrOFMessages,
             State#state{fwd_table = FwdTable1}};
        _ ->
            {reply, CurrOFMessages, State}
    end;

handle_call({handle_message, {flow_stats_reply, _, MsgBody}, CurrOFMessages},
        _From, State = #state{datapath_id = DatapathId}) ->
    [IpSrc, TCPSrc, PacketCount, DurationSec] =
    flow_stats_extract([ipv4_src,
                        tcp_src,
                        packet_count,
                        duration_sec], MsgBody),
    case packets_threshold_exceeed(PacketCount, DurationSec) of
        true ->
            OFMsg = drop_flow_mod(IpSrc, TCPSrc),
            {reply, CurrOFMessages ++ OFMsg, State};
        false ->
            schedule_flow_stats_request(DatapathId, IpSrc, TCPSrc),
            {reply, CurrOFMessages, State}
    end.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({remove_entry, Dpid, SrcMac},
            #state{fwd_table = FwdTable} = State) ->
    lager:debug("Removed forwarding entry in ~p: ~p => ~p",
                [Dpid, format_mac(SrcMac), maps:get(SrcMac,
                                                    FwdTable)]),
    {noreply, State#state{fwd_table = maps:remove(SrcMac, FwdTable)}};

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

handle_packet_in({_, Xid, PacketIn}, Dpid, FwdTable0) ->
    [IpSrc, TCPSrc] = packet_in_extract([ipv4_src, tcp_src], PacketIn),
    Matches = [{eth_type, 16#0800},
               {ipv4_src, IpSrc},
               {ip_proto, <<6>>},
               {tcp_src, TCPSrc},
               {tcp_dst, <<5222:16>>}],
    Instructions = [{apply_actions, [{output, 1, no_buffer}]}],
    FlowOpts = [{table_id, 0}, {priority, 150},
                {idle_timeout, ?FM_TIMEOUT_S(idle)},
                {hard_timeout, ?FM_TIMEOUT_S(hard)},
                {cookie, <<0, 0, 0, 0, 0, 0, 0, 200>>},
                {cookie_mask, <<0, 0, 0, 0, 0, 0, 0, 0>>}],
    FM = of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts),
    PO = packet_out(Xid, PacketIn, 1),
    schedule_flow_stats_request(Dpid, IpSrc, TCPSrc),
    {[FM, PO], FwdTable0}.

drop_flow_mod(IpSrc, TCPSrc) ->
    Matches = [{eth_type, 16#0800},
               {ipv4_src, IpSrc},
               {ip_proto, <<6>>},
               {tcp_src, TCPSrc},
               {tcp_dst, <<5222:16>>}],
    Instructions = [{apply_actions, []}],
    FlowOpts = [{table_id, 0}, {priority, 150},
                {idle_timeout, ?FM_TIMEOUT_S(idle)},
                {hard_timeout, ?FM_TIMEOUT_S(hard)},
                {cookie, <<0,0,0,0,0,0,0,200>>},
                {cookie_mask, <<0,0,0,0,0,0,0,0>>}],
    of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts).

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
packet_in_extract(buffer_id, PacketIn) ->
    proplists:get_value(buffer_id, PacketIn);
packet_in_extract(data, PacketIn) ->
    proplists:get_value(data, PacketIn);
packet_in_extract(reason, PacketIn) ->
    proplists:get_value(reason, PacketIn).

flow_stats_extract(Elements, FlowStats) when is_list(Elements) ->
    [flow_stats_extract(H, FlowStats) || H <- Elements];
flow_stats_extract(ipv4_src, FlowStats) ->
    proplists:get_value(ipv4_src, FlowStats);
flow_stats_extract(tcp_src, FlowStats) ->
    proplists:get_value(tcp_src, FlowStats);
flow_stats_extract(packet_count, FlowStats) ->
    proplists:get_value(packet_count, FlowStats);
flow_stats_extract(duration_sec, FlowStats) ->
    proplists:get_value(duration_sec, FlowStats).

format_mac(MacBin) ->
    Mac0 = [":" ++ integer_to_list(X, 16) || <<X>> <= MacBin],
    tl(lists:flatten(Mac0)).

schedule_flow_stats_request(DatapathId, IpSrc, TCPSrc) ->
    timer:send_after(?FLOW_STAT_REQUEST_INTERVAL,
                     {send_flow_stats_request,
                      DatapathId, TCPSrc, IpSrc}).

packets_threshold_exceeed(PacketCount, DurationSec) ->
    PacketCount/DurationSec/60 > ?PACKETS_THRESHOLD.
