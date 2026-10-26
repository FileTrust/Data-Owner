# do_state.py — all mutable globals shared across modules.
# Import this module as:  import do_state as S
# Read:   S.root, S.PKX_VALUE, etc.
# Write:  S.root = ..., S.PKX_VALUE = ...
# Never import * from this module in other modules.

# ── UI widgets ────────────────────────────────────────────────────────────────
root = None
result_text = None
pieces_listbox = None

selected_file_var = None
selected_datetime_var = None
entry_n = None
entry_t = None
entry_guardian_n = None
entry_guardian_t = None
entry_service_days = None
entry_device_id = None
entry_req_address = None
entry_policy_name = None
chk_var = None
auto_select_var = None
auto_quiet_info: bool = False

status_var = None
status_label = None
file_id_var = None
policy_status_var = None
staged_g_status_var = None
policy_vk_status_var = None
ida_info_var = None

guardians_listbox = None
guardian_rows = []
guardian_display_records = []
guardian_load_error = None

vault_keepers_listbox = None
vault_keeper_rows = {}          # iid → row dict
vault_keeper_load_error = None

# VK map state
vk_tab_view = None              # CTkTabview holding "Table" and "Map" sub-tabs
vk_map_widget = None            # TkinterMapView instance
vk_map_markers: list = []       # active map marker objects
vk_map_level: str = "world"     # "world" | "country" | "city"
vk_map_current_country: str = ""
vk_map_back_btn = None
vk_map_local_var = None         # StringVar for localhost node count label
policy_files_tree = None        # Treeview: the files inside the selected policy
date_button = None              # shows the chosen date, opens the picker
progress_box = None             # the frame holding bar + caption
progress_bar = None             # CTkProgressBar beside the status pill
progress_var = None             # StringVar: what the bar is counting
selected_upload_instance_id = None  # which file the pieces table is showing
upload_button = None            # disabled until the keepers have loaded
policy_active_button = None     # one button: Activate or Deactivate this policy
select_file_button = None
select_folder_button = None
vk_map_info_var = None          # StringVar for clicked-node info label

policies_tree = None
policy_detail_text = None
stored_pieces_tree = None   # treeview in Policies tab — shows VK-held pieces for deletion
req_book_tree = None
entry_req_name = None

# ── DKG key state ─────────────────────────────────────────────────────────────
PKX_VALUE = None
PKY_VALUE = None
LAST_PKX_VALUE = None
LAST_PKY_VALUE = None
KEY_EPOCH = None
ACTIVE_FILE_ID = None
ACTIVE_FILE_ID_HEX = None
ACTIVE_REFRESH_TARGET_VERSION = None
ACTIVE_REFRESH_FROM_VERSION = None

# ── In-memory policy / VK selections ─────────────────────────────────────────
staged_guardians: list = []         # staged before Create/Update Policy
policy_vk_peers: list = []          # VKs confirmed for current upload

# ── Background sync flag ──────────────────────────────────────────────────────
_chain_sync_running: bool = False
auto_upload_pending: bool = False
tray_icon = None
tray_thread = None
tray_available: bool = False

# ── Drop-folder watcher / queued upload state ────────────────────────────────
drop_folder_var = None
drop_folder_enabled_var = None
drop_folder_delete_from_vk_var = None
drop_folder_status_var = None
drop_folder_watcher_started: bool = False
drop_folder_seen: dict = {}
drop_folder_inventory: dict = {}
drop_folder_pending: dict = {}
drop_folder_queue: list = []
drop_folder_delete_queue: list = []
drop_folder_uploading: bool = False
drop_folder_deleting: bool = False
drop_folder_current_item: str = ""
drop_folder_settings_save_job = None

# ── Logging dedup ─────────────────────────────────────────────────────────────
_LOG_LAST_TIME: dict = {}

# ── Sort state for each table ─────────────────────────────────────────────────
_guardian_sort_state: dict = {"col": None, "reverse": False}
_vk_sort_state: dict = {"col": None, "reverse": False}
_pol_sort_state: dict = {"col": None, "reverse": False}
_req_book_sort_state: dict = {"col": None, "reverse": False}

account_balance_var = None     # StringVar for the header balance label

# Pop-out panels: the dashboard keeps a compact copy, these are the big ones.
log_window = None
about_window = None
log_window_text = None
pieces_window = None
pieces_window_tree = None
