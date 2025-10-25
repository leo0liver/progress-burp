from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IExtensionStateListener
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IMessageEditorController
from burp import ITab
from datetime import datetime
from email.utils import formatdate
from java.awt import BorderLayout
from java.awt import Color
from java.awt import Component
from java.awt import Dimension
from java.awt import Frame
from java.awt.event import ActionListener, FocusListener, ItemListener, ItemEvent
from java.lang import Class, ClassNotFoundException, Integer, Runnable, String
from java.sql import DriverManager, SQLException, Statement, Types
from javax.swing import (
    BoxLayout,
    ButtonGroup,
    GroupLayout,
    JButton,
    JCheckBox,
    JComboBox,
    JFileChooser,
    JLabel,
    JMenu,
    JMenuItem,
    JOptionPane,
    JPanel,
    JPopupMenu,
    JRadioButton,
    JScrollPane,
    JSeparator,
    JSplitPane,
    JTabbedPane,
    JTable,
    JTextField,
    SwingUtilities,
)
from javax.swing.event import DocumentListener
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from threading import Lock

import json
import os.path
import re


class DomainDict(object):
    def __init__(self, value_repository):
        self._value_repository = value_repository
        self._values = value_repository.get(
            self._get_storage_key(),
            self._get_default_values()
        )

    def get_values(self):
        return self._values

    def set_value(self, key, value):
        self._values[key] = value
        if key not in self._get_keys_excluded_from_storing():
            self._value_repository.set(self._get_storage_key(), self._values)

    def _get_default_values(self):
        return {}

    def _get_keys_excluded_from_storing(self):
        return []

    def _get_storage_key(self):
        return self.__class__.__name__


class Repository(object):
    def __init__(self, database):
        self._database = database
        self._last_object_id = 0
        self._objects = []

    def add(self, object):
        object.set_id(self._get_next_id())
        self._objects.append(object)
        if self._database.is_connected():
            self._insert_object(object)

    def delete_by_ids(self, ids):
        self.delete_by_list(
            self.find_by_ids(ids)
        )

    def delete_by_list(self, objects):
        ids = []
        for object in objects:
            ids.append(object.get_id())
            self._objects.remove(object)
        if self._database.is_connected():
            self._delete_objects(ids)

    def find_all(self):
        return self._objects

    def find_by_filters(self, filters):
        return filter(lambda object: all(f(object) for f in filters), self._objects)

    def find_by_id(self, id):
        return self.find_by_ids([id])[0]

    def find_by_ids(self, ids):
        return filter(lambda object: object.get_id() in ids, self._objects)

    def find_by_unique_key(self, unique_key):
        return filter(lambda object: object.get_unique_key() == unique_key, self._objects)

    def update_property_by_id(self, property, value, id):
        self.update_property_by_ids(property, value, [id])

    def update_property_by_ids(self, property, value, ids):
        setter_name = 'set_%s' % property
        map(lambda object: getattr(object, setter_name)(value), self.find_by_ids(ids))
        if self._database.is_connected():
            self._update_objects(property, value, ids)

    def _get_next_id(self):
        self._last_object_id += 1
        return self._last_object_id

    # persistence
    def init_persistence(self):
        if self._database.is_connected():
            self._create_table()
            for object in self._objects:
                self._insert_object(object)

    def load(self):
        if self._database.is_connected():
            self._objects = self._get_all_objects()
            if self._objects:
                self._last_object_id = self._objects[-1].get_id()

    # persistence (repository interface)
    def _create_table(self):
        pass

    def _delete_objects(self, ids):
        pass

    def _get_all_objects(self):
        return []

    def _insert_object(self, object):
        pass

    def _update_objects(self, property, value, ids):
        pass


class SelectedObjects(DomainDict):
    def __init__(self, object_repository, ui_services, value_repository):
        super(SelectedObjects, self).__init__(value_repository)
        self._object_repository = object_repository
        self._ui_services = ui_services

    # DomainDict
    def _get_default_values(self):
        return {
            'main_object_id': None,
            'object_ids': [],
        }

    def _get_keys_excluded_from_storing(self):
        return ['main_object_id', 'object_ids']

    # business logic
    def delete_selected_objects(self):
        if self._ui_services.confirm(
            'Are you sure you want to delete the selected %s?' % self._get_object_plural_name()
        ):
            self._object_repository.delete_by_ids(self._values['object_ids'])

    def _get_object_plural_name(self):
        pass


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Table(JTable):
    @staticmethod
    def _create_cell_renderer(column_name):
        pass

    def __init__(self):
        super(Table, self).__init__()
        self._model = self._create_model()
        self._prev_main_selected_object_id = None
        self._value_repository = ValueRepository()
        self.setModel(self._model)
        self.setAutoCreateRowSorter(True)
        self.setComponentPopupMenu(self._create_popup_menu())
        self._prepare_cell_renderers()
        self._restore_column_widths()
        EventBus().add_observer(self, [EventBus.EVENT_EXTENSION_UNLOADED])

    # JTable
    def valueChanged(self, event):
        super(Table, self).valueChanged(event)
        if not event.getValueIsAdjusting():
            self._execute_select_objects_command()
            self._execute_select_main_object_command()

    # Events
    def on_event(self, event_code, value):
        if event_code == EventBus.EVENT_EXTENSION_UNLOADED:
            self._save_column_widths()

    def _execute_select_objects_command(self):
        Application.get_instance().execute(
            SetDomainDictValueCommand(
                self._get_domain_dict_type(),
                'object_ids',
                self._model.map_object_indexes_to_ids(
                    [self.convertRowIndexToModel(i) for i in self.getSelectedRows()]
                )
            )
        )

    def _execute_select_main_object_command(self):
        main_object_id = None
        main_object_index = self.getSelectedRow()
        if main_object_index != -1:
            main_object_id = self._model.map_object_indexes_to_ids([self.convertRowIndexToModel(main_object_index)])[0]
        if main_object_id != self._prev_main_selected_object_id:
            Application.get_instance().execute(SetDomainDictValueCommand(
                self._get_domain_dict_type(),
                'main_object_id',
                main_object_id
            ))
            self._prev_main_selected_object_id = main_object_id

    def _prepare_cell_renderers(self):
        default_cell_renderer = DefaultTableCellRenderer()
        default_cell_renderer.setHorizontalAlignment(JLabel.LEFT)
        for column_name, column in self._get_columns():
            cell_renderer = self._create_cell_renderer(column_name)
            if cell_renderer is None:
                cell_renderer = default_cell_renderer
            column.setCellRenderer(cell_renderer)

    def _restore_column_widths(self):
        column_widths = self._value_repository.get(self._get_storage_key(), None)
        if column_widths:
            for column_name, column in self._get_columns():
                column.setPreferredWidth(column_widths[column_name])

    def _save_column_widths(self):
        column_widths = {}
        for column_name, column in self._get_columns():
            column_widths[column_name] = column.getWidth()
        self._value_repository.set(self._get_storage_key(), column_widths)

    def _get_columns(self):
        for i in range(self.getColumnModel().getColumnCount()):
            yield self.getColumnName(i), self.getColumnModel().getColumn(i)

    def _get_storage_key(self):
        return self.__class__.__name__ 


class TableColumnModel(object):
    def __init__(self):
        self._columns = self._prepare_columns()

    def get_class(self, column_index):
        return self._columns[column_index][1]

    def get_count(self):
        return len(self._columns)

    def get_name(self, column_index):
        return self._columns[column_index][0]

    def is_array(self, column_index):
        return self._columns[column_index][2]

    def is_editable(self, column_index):
        return self._columns[column_index][3]


class TableModel(AbstractTableModel):
    __metaclass__ = Singleton

    def __init__(self):
        super(TableModel, self).__init__()
        self._column_model = self._create_column_model()
        self._objects = []

    # AbstractTableModel
    def getColumnClass(self, column_index):
        return self._column_model.get_class(column_index)

    def getColumnCount(self):
        return self._column_model.get_count()

    def getColumnName(self, column_index):
        return self._column_model.get_name(column_index)

    def getRowCount(self):
        return len(self._objects)

    def getValueAt(self, row_index, column_index):
        property = self._get_property_name(column_index)
        value = getattr(self._objects[row_index], 'get_%s' % property)()
        return InfrastructureHelpers.join(value) if self._column_model.is_array(column_index) else value

    def isCellEditable(self, _, column_index):
        return self._column_model.is_editable(column_index)

    def setValueAt(self, value, row_index, column_index):
        property = self.getColumnName(column_index).lower()
        if self._column_model.is_array(column_index):
            value = InfrastructureHelpers.split(value)
        Application.get_instance().execute(self._create_set_object_property_application_command(
            self._objects[row_index].get_id(),
            property,
            value
        ))

    def map_object_indexes_to_ids(self, object_indexes):
        return [self._objects[i].get_id() for i in object_indexes]

    def display(self, objects):
        self._objects = objects
        self.fireTableDataChanged()

    def _get_property_name(self, column_index):
        return self.getColumnName(column_index).lower().replace(' ', '_')


class TablePopupMenu(JPopupMenu, ActionListener):
    def __init__(self):
        super(TablePopupMenu, self).__init__()
        self._labels = self._prepare_labels()
        self._prepare_menu(self._labels, self)

    # ActionListener
    def actionPerformed(self, event):
        Application.get_instance().execute(self._create_application_command(
            event.getActionCommand()
        ))

    def _prepare_menu(self, labels, parent):
        for label in sorted(labels.keys()):
            if labels[label]:
                menu_item = JMenu(label)
                self._prepare_menu(labels[label], menu_item)
            else:
                menu_item = JMenuItem(label)
                menu_item.addActionListener(self)
            parent.add(menu_item)


class TextFieldPanel(JPanel, FocusListener):
    __metaclass__ = Singleton

    def __init__(self):
        super(TextFieldPanel, self).__init__()
        self._text_field = None

    def focusGained(self, event):
        pass

    def focusLost(self, event):
        Application.get_instance().execute(SetDomainDictValueCommand(
            self._get_domain_dict_type(),
            self._get_domain_dict_key(),
            InfrastructureHelpers.split(self._text_field.getText())
        ))

    def display(self, values):
        self._prepare_components(values)

    def _prepare_components(self, values):
        self._text_field = JTextField()
        self._text_field.setColumns(30)
        self._text_field.setEditable(True)
        self._text_field.setText(InfrastructureHelpers.join(values[self._get_domain_dict_key()]))
        self._text_field.addFocusListener(self)
        self.add(self._text_field)


class VisibleObjects(DomainDict):
    def __init__(self, object_repository, ui_services, value_repository):
        super(VisibleObjects, self).__init__(value_repository)
        self._object_repository = object_repository
        self._ui_services = ui_services

    def display(self):
        self._ui_services.display_objects(
            self._get_object_type(),
            self._find_visible_objects()
        )

    def set_value(self, key, value):
        super(VisibleObjects, self).set_value(key, value)
        self.display()

    def _find_visible_objects(self):
        return self._object_repository.find_by_filters(self._get_filters())


class AddPathPatternCommand(object):
    def __init__(self):
        pass


class AddPathPatternCommandHandler(object):
    def __init__(
        self,
        duplicate_items,
        duplicate_path_patterns,
        selected_items,
        visible_items,
        visible_path_patterns
    ):
        self._duplicate_items = duplicate_items
        self._duplicate_path_patterns = duplicate_path_patterns
        self._selected_items = selected_items
        self._visible_items = visible_items
        self._visible_path_patterns = visible_path_patterns

    def handle(self, command):
        path_pattern, origin_item = self._selected_items.create_path_pattern_from_main_selected_item()
        if path_pattern:
            if self._duplicate_path_patterns.add_path_pattern(path_pattern):
                self._duplicate_items.delete_duplicate_items_by_path_pattern(path_pattern, origin_item)
                self._visible_items.display()
                self._visible_path_patterns.display()


class Application(object):
    ACTION_TOOLS = ['Intruder', 'Repeater', 'Scanner']
    ITEM_STATUSES = ['Blocked', 'Done', 'Ignored', 'In progress', 'New', 'Postponed']
    SCOPE_TOOLS = ['Proxy', 'Repeater', 'Target']

    _instance = None

    @staticmethod
    def get_instance():
        return Application._instance

    @staticmethod
    def set_instance(instance):
        Application._instance = instance

    def __init__(
        self,
        burp_services,
        database,
        highlight_settings,
        item_repository,
        path_pattern_repository,
        ui_services,
        value_repository
    ):
        duplicate_items = DuplicateItems(item_repository, path_pattern_repository, value_repository)
        duplicate_path_patterns = DuplicatePathPatterns(path_pattern_repository)
        persistence = Persistence(database, item_repository, path_pattern_repository, ui_services, value_repository)
        pre_analyze_validator = PreAnalyzeValidator(value_repository)
        pre_process_validator = PreProcessValidator(value_repository)
        selected_items = SelectedItems(burp_services, item_repository, ui_services, value_repository)
        selected_path_patterns = SelectedPathPatterns(path_pattern_repository, ui_services, value_repository)
        visible_items = VisibleItems(item_repository, ui_services, value_repository)
        visible_path_patterns = VisiblePathPatterns(path_pattern_repository, ui_services, value_repository)

        self._command_handlers = {
            AddPathPatternCommand.__name__: AddPathPatternCommandHandler(
                duplicate_items,
                duplicate_path_patterns,
                selected_items,
                visible_items,
                visible_path_patterns
            ),
            DeleteSelectedObjectsCommand.__name__: DeleteSelectedObjectsCommandHandler(
                selected_items,
                selected_path_patterns,
                visible_items,
                visible_path_patterns
            ),
            InitCommand.__name__: InitCommandHandler(
                duplicate_items,
                highlight_settings,
                persistence,
                pre_analyze_validator,
                pre_process_validator,
                selected_items,
                ui_services,
                visible_items,
                visible_path_patterns
            ),
            MakePreAnalyzeValidationCommand.__name__: MakePreAnalyzeValidationCommandHandler(
                pre_analyze_validator
            ),
            MakePreProcessValidationCommand.__name__: MakePreProcessValidationCommandHandler(
                pre_process_validator
            ),
            ProcessHttpDialogCommand.__name__: ProcessHttpDialogCommandHandler(
                duplicate_items,
                visible_items
            ),
            SendSelectedItemsToToolCommand.__name__: SendSelectedItemsToToolCommandHandler(
                selected_items,
                visible_items
            ),
            SetDomainDictValueCommand.__name__: SetDomainDictValueCommandHandler(
                duplicate_items,
                highlight_settings,
                persistence,
                pre_analyze_validator,
                pre_process_validator,
                selected_items,
                selected_path_patterns,
                visible_items
            ),
            SetItemPropertyCommand.__name__: SetItemPropertyCommandHandler(
                item_repository,
                visible_items
            ),
            SetSelectedItemPropertiesCommand.__name__: SetSelectedItemPropertiesCommandHandler(
                selected_items,
                visible_items
            )
        }
        self.execute(InitCommand())

    def execute(self, command):
        return (self._command_handlers[command.__class__.__name__]).handle(command)


class BurpCallbacks(object):
    _instance = None

    def __init__(self):
        pass

    @staticmethod
    def get_instance():
        return BurpCallbacks._instance

    @staticmethod
    def set_instance(instance):
        BurpCallbacks._instance = instance


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        BurpCallbacks.set_instance(callbacks)
        BurpHelpers.set_instance(callbacks.getHelpers())
        listener = HttpListener()
        self._prepare_application(listener)
        callbacks.addSuiteTab(ProgressTab())
        callbacks.registerExtensionStateListener(self)
        callbacks.registerHttpListener(listener)
        callbacks.setExtensionName('Progress Tracker v1.1')

    def extensionUnloaded(self):
        EventBus().notify(EventBus.EVENT_EXTENSION_UNLOADED, None)

    def _prepare_application(self, listener):
        database = Database(Logger())
        value_repository = ValueRepository()
        item_repository = ItemRepository(database)
        path_pattern_repository = PathPatternRepository(database)
        highlight_settings = HighlightSettings(value_repository)
        duplicate_items = DuplicateItems(item_repository, path_pattern_repository, value_repository)
        listener.set_dependencies(duplicate_items, highlight_settings)
        Application.set_instance(Application(
            BurpServices(),
            database,
            highlight_settings,
            item_repository,
            path_pattern_repository,
            UIServices(),
            value_repository
        ))


class BurpHelpers(object):
    _instance = None

    def __init__(self):
        pass

    @staticmethod
    def get_instance():
        return BurpHelpers._instance

    @staticmethod
    def set_instance(instance):
        BurpHelpers._instance = instance


class BurpServices(object):
    def __init__(self):
        self._burp_callbacks = BurpCallbacks.get_instance()

    def send_items_to_tool(self, items, tool_name):
        for item in items:
            params = [
                item.get_host(),
                item.get_port(),
                item.get_protocol() == 'https',
                item.get_request().getBuffer()
            ]
            if tool_name == 'Repeater':
                params.append(None)
                self._burp_callbacks.sendToRepeater(*params)
            elif tool_name == 'Intruder':
                self._burp_callbacks.sendToIntruder(*params)
            elif tool_name == 'Scanner':
                self._burp_callbacks.doActiveScan(*params)


class CapturingPanel(JPanel, ItemListener):
    __metaclass__ = Singleton

    _OPTIONS = ['On', 'Off']

    def __init__(self):
        super(CapturingPanel, self).__init__()
        self._buttons = []

    def display(self, values):
        self.add(JLabel('<html><b>Capturing:</b></html'))
        button_group = ButtonGroup()
        for option in self._OPTIONS:
            button = JRadioButton(option)
            button.setSelected(option == values['capturing'])
            button.addItemListener(self)
            button_group.add(button)
            self._buttons.append(button)
            self.add(button)

    def itemStateChanged(self, event):
        for button in self._buttons:
            if button.isSelected():
                Application.get_instance().execute(SetDomainDictValueCommand(
                    SetDomainDictValueCommand.TYPE_PRE_ANALYZE_VALIDATOR,
                    'capturing',
                    button.getLabel()
                ))
                break


class CheckBoxPanel(JPanel, ItemListener):
    __metaclass__ = Singleton

    def __init__(self):
        super(CheckBoxPanel, self).__init__()
        self._check_box = None

    def itemStateChanged(self, event):
        Application.get_instance().execute(SetDomainDictValueCommand(
            self._get_domain_dict_type(),
            self._get_domain_dict_key(),
            self._check_box.isSelected()
        ))

    def display(self, values):
        self._check_box = JCheckBox(self._get_label())
        self._check_box.setSelected(values[self._get_domain_dict_key()])
        self._check_box.addItemListener(self)
        self.add(self._check_box)


class Database(object):
    @staticmethod
    def get_driver_name():
        return 'SQLite'

    @staticmethod
    def is_driver_loaded():
        try:
            Class.forName('org.sqlite.JDBC')
            return True
        except ClassNotFoundException:
            return False

    def __init__(self, logger):
        self._connection = None
        self._logger = logger
        EventBus().add_observer(self, [EventBus.EVENT_EXTENSION_UNLOADED])

    # Events
    def on_event(self, event_code, value):
        if event_code == EventBus.EVENT_EXTENSION_UNLOADED:
            if self.is_connected():
                self.disconnect()

    def connect(self, database_path):
        try:
            Class.forName('org.sqlite.JDBC')
            self._connection = DriverManager.getConnection('jdbc:sqlite:%s' % database_path)
            self._connection.setAutoCommit(True)
        except ClassNotFoundException as e:
            self._log_error(e.getMessage())
        except SQLException as e:
            self._log_error(e.getMessage())

    def disconnect(self):
        try:
            self._connection.close()
        except SQLException as e:
            self._log_error(e.getMessage())

    def is_connected(self):
        return self._connection is not None

    # queries
    def delete(self, query, params=()):
        self._execute_update(query, params)

    def execute(self, query, params=()):
        try:
            statement = self._prepare_statement(query, params)
            statement.execute()
            statement.close()
        except SQLException as e:
            self._log_error(e.getMessage())

    def insert(self, query, params=()):
        self._execute_update(query, params)

    def select(self, query, params=()):
        try:
            statement = self._prepare_statement(query, params)
            result_set = statement.executeQuery()
            meta_data = result_set.getMetaData()
            column_count = meta_data.getColumnCount()
            column_types = [meta_data.getColumnType(i+1) for i in range(column_count)]
            while result_set.next():
                row = []
                for i in range(column_count):
                    column_index = i + 1
                    if column_types[i] == Types.INTEGER:
                        value = result_set.getLong(column_index)
                    else:
                        value = result_set.getString(column_index)
                    row.append(value)
                yield row
            statement.close()
        except SQLException as e:
            self._log_error(e.getMessage())

    def update(self, query, params=()):
        self._execute_update(query, params)

    def _execute_update(self, query, params):
        try:
            statement = self._prepare_statement(query, params)
            statement.executeUpdate()
            statement.close()
        except SQLException as e:
            self._log_error(e.getMessage())

    def _prepare_statement(self, query, params):
        statement = self._connection.prepareStatement(query, Statement.NO_GENERATED_KEYS)
        i = 1
        for param in params:
            if isinstance(param, (int, long)):
                statement.setLong(i, param)
            else:
                statement.setString(i, param)
            i += 1
        return statement

    def _log_error(self, message):
        self._logger.error('Database error: ' + message)


class DatabasePanel(JPanel, ActionListener):
    __metaclass__ = Singleton

    def __init__(self):
        super(DatabasePanel, self).__init__()
        self._button = None
        self._text_field = None

    def actionPerformed(self, event):
        database_path = UIHelpers.choose_file()
        if database_path:
            if Application.get_instance().execute(SetDomainDictValueCommand(
                SetDomainDictValueCommand.TYPE_PERSISTENCE,
                'database_path',
                database_path
            )):
                self._text_field.setText(database_path)

    def display(self, values):
        self._prepare_components(values)

    def _prepare_components(self, values):
        self._text_field = JTextField()
        self._text_field.setColumns(30)
        self._text_field.setEditable(False)
        self._text_field.setText(values['database_path'])
        self.add(self._text_field)
        button = JButton('Save as...')
        button.addActionListener(self)
        self.add(button)


class DeleteSelectedObjectsCommand(object):
    TYPE_ITEM = 1
    TYPE_PATH_PATTERN = 2

    def __init__(self, type):
        self.type = type


class DeleteSelectedObjectsCommandHandler(object):
    def __init__(self, selected_items, selected_path_patterns, visible_items, visible_path_patterns):
        self._selected_object_handlers = {
            DeleteSelectedObjectsCommand.TYPE_ITEM: selected_items,
            DeleteSelectedObjectsCommand.TYPE_PATH_PATTERN: selected_path_patterns,
        }
        self._visible_object_handlers = {
            DeleteSelectedObjectsCommand.TYPE_ITEM: visible_items,
            DeleteSelectedObjectsCommand.TYPE_PATH_PATTERN: visible_path_patterns,
        }

    def handle(self, command):
        self._selected_object_handlers[command.type].delete_selected_objects()
        self._visible_object_handlers[command.type].display()


class DomainDictWithLock(DomainDict):
    def __init__(self, value_repository):
        super(DomainDictWithLock, self).__init__(value_repository)
        self._lock = Lock()

    def set_value(self, key, value):
        with self._lock:
            super(DomainDictWithLock, self).set_value(key, value)


class DuplicateItems(DomainDict):
    def __init__(self, item_repository, path_pattern_repository, value_repository):
        super(DuplicateItems, self).__init__(value_repository)
        self._item_repository = item_repository
        self._path_pattern_repository = path_pattern_repository

    # DomainDict
    def _get_default_values(self):
        return {
            'overwrite_duplicate_items': True,
        }

    # business logic
    def add_item(self, item):
        duplicate_items = self._find_duplicate_items(item)
        if duplicate_items:
            if self._values['overwrite_duplicate_items']:
                self._overwrite_duplicate_items(duplicate_items, item)
        else:
            self._add_item(item)

    def delete_duplicate_items_by_path_pattern(self, path_pattern, origin_item):
        duplicate_items = self._item_repository.find_by_filters([
            ItemsByPathPatternsFilter([path_pattern])
        ])
        if origin_item in duplicate_items:
            duplicate_items.remove(origin_item)
        self._item_repository.delete_by_list(duplicate_items)

    def _add_item(self, item):
        self._item_repository.add(item)

    def _find_duplicate_items(self, item):
        duplicate_items = self._item_repository.find_by_unique_key(item.get_unique_key())
        if not duplicate_items:
            path_patterns = self._path_pattern_repository.find_by_filters([PathPatternsByItemFilter(item)])
            duplicate_items = self._item_repository.find_by_filters([ItemsByPathPatternsFilter(path_patterns)])
        return duplicate_items

    def _overwrite_duplicate_items(self, duplicate_items, item):
        item.copy_state_from(duplicate_items[-1])
        self._item_repository.delete_by_list(duplicate_items)
        self._add_item(item)


class DuplicatePathPatterns(object):
    def __init__(self, path_pattern_repository):
        self._path_pattern_repository = path_pattern_repository

    def add_path_pattern(self, path_pattern):
        if self._has_duplicate_path_patterns(path_pattern):
            return False
        self._path_pattern_repository.add(path_pattern)
        return True

    def _has_duplicate_path_patterns(self, path_pattern):
        return len(self._path_pattern_repository.find_by_unique_key(path_pattern.get_unique_key())) > 0


class EventBus(object):
    __metaclass__ = Singleton

    EVENT_EXTENSION_UNLOADED = 1

    def __init__(self):
        self._observers = {}

    def add_observer(self, observer, event_codes):
        for event_code in event_codes:
            if event_code not in self._observers:
                self._observers[event_code] = []
            self._observers[event_code].append(observer)

    def notify(self, event_code, value):
        for observer in self._observers[event_code]:
            observer.on_event(event_code, value)


class ExcludedExtensionsPanel(TextFieldPanel):
    def _get_domain_dict_key(self):
        return 'excluded_extensions'

    def _get_domain_dict_type(self):
        return SetDomainDictValueCommand.TYPE_PRE_PROCESS_VALIDATOR


class ExcludedStatusCodesPanel(TextFieldPanel):
    def _get_domain_dict_key(self):
        return 'excluded_status_codes'

    def _get_domain_dict_type(self):
        return SetDomainDictValueCommand.TYPE_PRE_PROCESS_VALIDATOR


class ExecuteApplicationCommandInGuiThread(Runnable):
    def __init__(self, command):
        self.command = command

    def run(self):
        Application.get_instance().execute(self.command)


class HttpDialogEditor(IMessageEditorController):
    __metaclass__ = Singleton

    def __init__(self):
        self._burp_callbacks = BurpCallbacks.get_instance()
        self._burp_helpers = BurpHelpers.get_instance()
        self._request_editor = self._burp_callbacks.createMessageEditor(self, False)
        self._response_editor = self._burp_callbacks.createMessageEditor(self, False)
        self._item = None

    # IMessageEditorController
    def getHttpService(self):
        return self._burp_helpers.buildHttpService(
            self._item.get_host(),
            self._item.get_port(),
            self._item.get_protocol()
        )

    def getRequest(self):
        return self._item.get_request().getBuffer()

    def getResponse(self):
        return self._item.get_response().getBuffer()

    def get_request_editor_component(self):
        return self._request_editor.getComponent()

    def get_response_editor_component(self):
        return self._response_editor.getComponent()

    def display(self, item):
        if item is not None:
            self._item = item
            self._request_editor.setMessage(self._item.get_request().getBuffer(), True)
            self._response_editor.setMessage(self._item.get_response().getBuffer(), False)


class HttpListener(IHttpListener):
    def __init__(self):
        self._burp_callbacks = BurpCallbacks.get_instance()
        self._burp_helpers = BurpHelpers.get_instance()
        self._duplicate_items = None
        self._highlight_settings = None

    def set_dependencies(self, duplicate_items, highlight_settings):
        self._duplicate_items = duplicate_items
        self._highlight_settings = highlight_settings

    def _highlight_item_in_proxy(self, tool_flag, message_info):
        settings = self._highlight_settings.get_values()
        if not settings.get('highlight_enabled'):
            return

        request_info, response_info = self._analyze_message(message_info)
        
        # Create a temporary item to find duplicates
        path = self._get_graphql_operation_name(request_info, message_info.getRequest()) or request_info.getUrl().getPath()
        temp_item = Item(None, message_info.getHttpService().getHost(), None, request_info.getMethod(), path, message_info.getHttpService().getPort(), message_info.getHttpService().getProtocol(), None, None, None, None, None, None)

        found_items = self._duplicate_items._find_duplicate_items(temp_item)
        
        if found_items:
            # Existing item logic
            item = found_items[-1] 
            if item.get_status() == settings.get('highlight_status'):
                message_info.setHighlight(settings.get('highlight_color'))
        else:
            # New item logic
            if settings.get('highlight_status') == 'New':
                # Check if this item is destined to be added to the repository
                if self._is_pre_analyze_validation_pass(tool_flag) and self._is_pre_process_validation_pass(request_info, response_info):
                    message_info.setHighlight(settings.get('highlight_color'))

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        # Synchronous highlighting for Proxy tool
        if self._duplicate_items and tool_flag == IBurpExtenderCallbacks.TOOL_PROXY and not message_is_request:
            self._highlight_item_in_proxy(tool_flag, message_info)

        # Asynchronous item processing (existing logic)
        if tool_flag not in [
            IBurpExtenderCallbacks.TOOL_PROXY,
            IBurpExtenderCallbacks.TOOL_REPEATER,
            IBurpExtenderCallbacks.TOOL_TARGET,
        ]:
            return
        if message_is_request:
            return
        if not self._is_pre_analyze_validation_pass(tool_flag):
            return
        request_info, response_info = self._analyze_message(message_info)
        if not self._is_pre_process_validation_pass(request_info, response_info):
            return
        SwingUtilities.invokeLater(ExecuteApplicationCommandInGuiThread(
            self._create_process_http_dialog_command(tool_flag, request_info, message_info)
        ))

    def _analyze_message(self, message_info):
        return \
            self._burp_helpers.analyzeRequest(message_info), \
            self._burp_helpers.analyzeResponse(message_info.getResponse())

    def _create_make_pre_analyze_validation_command(self, tool_flag):
        return MakePreAnalyzeValidationCommand(
            self._burp_callbacks.getToolName(tool_flag)
        )

    def _create_make_pre_process_validation_command(self, request_info, response_info):
        return MakePreProcessValidationCommand(
            request_info.getUrl().getPath().rsplit('.', 1)[-1].lower(),
            self._burp_callbacks.isInScope(request_info.getUrl()),
            str(response_info.getStatusCode())
        )

    def _get_graphql_operation_name(self, request_info, request_bytes):
        try:
            if request_info.getMethod() != 'POST':
                return None

            headers = request_info.getHeaders()
            content_type = None
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.split(":", 1)[1].strip()
                    break

            if not (content_type and (content_type.startswith('application/json') or content_type.startswith('application/graphql'))):
                return None

            body_offset = request_info.getBodyOffset()
            body_bytes = request_bytes[body_offset:]
            body_str = self._burp_helpers.bytesToString(body_bytes)

            if '"operationName"' not in body_str:
                return None

            json_body = json.loads(body_str)
            operation_name = json_body.get('operationName')

            if operation_name:
                return "[GraphQL] %s" % operation_name
        except Exception:
            # Ignore exceptions during parsing
            pass

        return None

    def _create_process_http_dialog_command(self, tool_flag, request_info, message_info):
        request_bytes = message_info.getRequest()
        operation_name = self._get_graphql_operation_name(request_info, request_bytes)
        path = operation_name if operation_name is not None else request_info.getUrl().getPath()

        return ProcessHttpDialogCommand(
            request_info.getMethod(),
            self._save_to_temp_file(request_bytes),
            self._save_to_temp_file(message_info.getResponse()),
            datetime.now().strftime('%H:%M:%S %d %b %Y'),
            self._burp_callbacks.getToolName(tool_flag),
            request_info.getUrl(),
            path
        )

    def _save_to_temp_file(self, data):
        return self._burp_callbacks.saveToTempFile(data)

    def _is_pre_analyze_validation_pass(self, tool_flag):
        return Application.get_instance().execute(
            self._create_make_pre_analyze_validation_command(tool_flag)
        )

    def _is_pre_process_validation_pass(self, request_info, response_info):
        return Application.get_instance().execute(
            self._create_make_pre_process_validation_command(request_info, response_info)
        )


class HttpRequestResponse(IHttpRequestResponse):
    def __init__(self, http_service, request, response):
        self._http_service = http_service
        self._request = request
        self._response = response

    def getComment(self):
        pass

    def getHighlight(self):
        pass

    def getHttpService(self):
        return self._http_service

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def setComment(self, comment):
        pass

    def setHighlight(self, color):
        pass

    def setHttpService(self, http_service):
        pass

    def setRequest(self, message):
        pass

    def setResponse(self, message):
        pass


class InfrastructureHelpers(object):
    @staticmethod
    def join(values):
        return ','.join(values)

    @staticmethod
    def split(value):
        return value.replace(',', ' ').split()


class InitCommand(object):
    def __init__(self):
        pass


class InitCommandHandler(object):
    def __init__(
            self,
            duplicate_items,
            highlight_settings,
            persistence,
            pre_analyze_validator,
            pre_process_validator,
            selected_items,
            ui_services,
            visible_items,
            visible_path_patterns
    ):
        self._domain_dicts = [
            duplicate_items,
            highlight_settings,
            persistence,
            pre_analyze_validator,
            pre_process_validator,
            selected_items,
            visible_items
        ]
        self._ui_services = ui_services
        self._visible_objects_handlers = [
            visible_items,
            visible_path_patterns,
        ]

    def handle(self, command):
        values = {}
        for domain_dict in self._domain_dicts:
            values.update(domain_dict.get_values())
        self._ui_services.display_panels(values)
        for visible_objects_handler in self._visible_objects_handlers:
            visible_objects_handler.display()


class Item(object):
    def __init__(
            self,
            comment,
            host,
            id,
            method,
            path,
            port,
            protocol,
            request,
            response,
            status,
            tags,
            time,
            tool
    ):
        self._comment = comment
        self._host = host
        self._id = id
        self._method = method
        self._path = path
        self._port = port
        self._protocol = protocol
        self._request = request
        self._response = response
        self._status = status
        self._tags = tags
        self._time = time
        self._tool = tool

    # get & set
    def get_comment(self):
        return self._comment

    def get_host(self):
        return self._host

    def get_id(self):
        return self._id

    def get_method(self):
        return self._method

    def get_path(self):
        return self._path

    def get_port(self):
        return self._port

    def get_protocol(self):
        return self._protocol

    def get_request(self):
        return self._request

    def get_response(self):
        return self._response

    def get_status(self):
        return self._status

    def get_tags(self):
        return self._tags

    def get_time(self):
        return self._time

    def get_tool(self):
        return self._tool

    def set_comment(self, comment):
        self._comment = comment

    def set_id(self, id):
        self._id = id

    def set_status(self, status):
        self._status = status

    def set_tags(self, tags):
        self._tags = tags

    # business logic
    def copy_state_from(self, item):
        self._comment = item.get_comment()
        self._status = item.get_status()
        self._tags = item.get_tags()

    def get_target(self):
        return '%s://%s:%d' % (self._protocol, self._host, self._port)

    def get_unique_key(self):
        return self.get_target() + self.get_method() + self.get_path()

    def has_all_tags_of(self, tags):
        item_tags = set(self._tags)
        return tags.issubset(item_tags)

    def has_any_tag_of(self, tags):
        item_tags = set(self._tags)
        return bool(tags.intersection(item_tags))

    def is_status_one_of(self, statuses):
        return self._status in statuses


class ItemRepository(Repository):
    def __init__(self, database):
        super(ItemRepository, self).__init__(database)
        self._burp_callbacks = BurpCallbacks.get_instance()
        self._burp_helpers = BurpHelpers.get_instance()

    # persistence
    def _create_table(self):
        self._database.execute(
            'CREATE TABLE items('
            'comment TEXT NOT NULL,
            'host TEXT NOT NULL,
            'id INTEGER PRIMARY KEY,
            'method TEXT NOT NULL,
            'path TEXT NOT NULL,
            'port INTEGER NOT NULL,
            'protocol TEXT NOT NULL,
            'request TEXT NOT NULL,
            'response TEXT NOT NULL,
            'status TEXT NOT NULL,
            'tags TEXT NOT NULL,
            'time TEXT NOT NULL,
            'tool TEXT NOT NULL,
            'UNIQUE(protocol, host, port, method, path) ON CONFLICT IGNORE)'
        )

    def _delete_objects(self, ids):
        self._database.delete('DELETE FROM items WHERE id in (%s)' % ','.join(map(str, ids)))

    def _get_all_objects(self):
        items = []
        for row in self._database.select(
                'SELECT '
                'comment, host, id, method, path, port, protocol, request, response, status, tags, time, tool '
                'FROM items '
                'ORDER BY id'
        ):
            row[7] = self._decode_data(row[7])
            row[8] = self._decode_data(row[8])
            row[10] = InfrastructureHelpers.split(row[10])
            items.append(Item(*row))
        return items

    def _insert_object(self, item):
        self._database.insert(
            'INSERT INTO '
            'items(comment, host, id, method, path, port, protocol, request, response, status, tags, time, tool) '
            'values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                item.get_comment(),
                item.get_host(),
                item.get_id(),
                item.get_method(),
                item.get_path(),
                item.get_port(),
                item.get_protocol(),
                self._encode_data(item.get_request()),
                self._encode_data(item.get_response()),
                item.get_status(),
                InfrastructureHelpers.join(item.get_tags()),
                item.get_time(),
                item.get_tool(),
            )
        )

    def _update_objects(self, property, value, ids):
        if property == 'tags':
            value = InfrastructureHelpers.join(value)
        self._database.update(
            'UPDATE items SET %s = ? WHERE id in (%s)' % (property, ','.join(map(str, ids))),
            (value, )
        )

    def _decode_data(self, data):
        return self._burp_callbacks.saveToTempFile(self._burp_helpers.base64Decode(data))

    def _encode_data(self, data):
        return self._burp_helpers.base64Encode(data.getBuffer())


class ItemsBar(JPanel):
    def __init__(self):
        super(ItemsBar, self).__init__()
        self.add(StatusPanel())
        self.add(self._prepare_separator())
        self.add(TagPanel())
        self.add(TagOperatorPanel())
        self.add(self._prepare_separator())
        self.add(CapturingPanel())

    def _prepare_separator(self):
        separator = JSeparator(JSeparator.VERTICAL)
        separator.setPreferredSize(Dimension(2, 30))
        return separator


class ItemsByPathPatternsFilter(object):
    def __init__(self, path_patterns):
        self._path_patterns = path_patterns

    def __call__(self, *args, **kwargs):
        for path_pattern in self._path_patterns:
            if path_pattern.is_item_matched(args[0]):
                return True
        return False


class ItemsByStatusesFilter(object):
    def __init__(self, statuses):
        self._statuses = statuses

    def __call__(self, *args, **kwargs):
        return args[0].is_status_one_of(self._statuses)


class ItemsByTagsFilter(object):
    def __init__(self, tags, operator):
        self._tags = set(tags)
        self._operator = operator

    def __call__(self, *args, **kwargs):
        item = args[0]
        if self._operator == 'AND':
            return item.has_all_tags_of(self._tags)
        return item.has_any_tag_of(self._tags)


class ItemsColumnModel(TableColumnModel):
    @staticmethod
    def _prepare_columns():
        return [
            # name, class, is array?, is editable?
            ('Id', Integer, False, False),
            ('Path', String, False, False),
            ('Method', String, False, False),
            ('Status', String, False, False),
            ('Tags', String, True, True),
            ('Comment', String, False, True),
            ('Target', String, False, False),
            ('Tool', String, False, False),
            ('Time', String, False, False),
        ]


class ItemsModel(TableModel):
    @staticmethod
    def _create_column_model():
        return ItemsColumnModel()

    @staticmethod
    def _create_set_object_property_application_command(id, property, value):
        return SetItemPropertyCommand(id, property, value)


class ItemsPanel(JPanel):
    def __init__(self):
        super(ItemsPanel, self).__init__()
        self.setLayout(BorderLayout())
        self.add(ItemsBar(), BorderLayout.PAGE_START)
        self.add(ItemsView(), BorderLayout.CENTER)


class ItemsPopupMenu(TablePopupMenu):
    def __init__(self):
        super(ItemsPopupMenu, self).__init__()

    @staticmethod
    def _create_application_command(command):
        if command == 'Add path pattern':
            return AddPathPatternCommand()
        if command == 'Delete':
            return DeleteSelectedObjectsCommand(DeleteSelectedObjectsCommand.TYPE_ITEM)
        if command in Application.ACTION_TOOLS:
            return SendSelectedItemsToToolCommand(command)
        if command == 'Set comment':
            return SetSelectedItemPropertiesCommand('comment', None)
        if command in Application.ITEM_STATUSES:
            return SetSelectedItemPropertiesCommand('status', command)
        if command == 'Set tags':
            return SetSelectedItemPropertiesCommand('tags', None)

    @staticmethod
    def _prepare_labels():
        labels = {
            'Add path pattern': {},
            'Delete': {},
            'Send to': {},
            'Set comment': {},
            'Set status': {},
            'Set tags': {}
        }
        for action_tool in Application.ACTION_TOOLS:
            labels['Send to'][action_tool] = {}
        for item_status in Application.ITEM_STATUSES:
            labels['Set status'][item_status] = {}
        return labels


class ItemsTable(Table):
    @staticmethod
    def _create_cell_renderer(column_name):
        if column_name == 'Status':
            return StatusCellRenderer()

    @staticmethod
    def _create_model():
        return ItemsModel()

    @staticmethod
    def _create_popup_menu():
        return ItemsPopupMenu()

    @staticmethod
    def _get_domain_dict_type():
        return SetDomainDictValueCommand.TYPE_SELECTED_ITEMS


class ItemsView(JSplitPane):
    def __init__(self):
        super(ItemsView, self).__init__(JSplitPane.VERTICAL_SPLIT)
        self._prepare_table_view()
        self._prepare_http_dialog_editor_view()

    def _prepare_table_view(self):
        self.setTopComponent(JScrollPane(ItemsTable()))

    def _prepare_http_dialog_editor_view(self):
        editor = HttpDialogEditor()
        editor_view = JTabbedPane()
        editor_view.addTab('Request', editor.get_request_editor_component())
        editor_view.addTab('Response', editor.get_response_editor_component())
        self.setBottomComponent(editor_view)


class Logger(object):
    def __init__(self):
        self._burp_callbacks = BurpCallbacks.get_instance()

    def error(self, message):
        self._burp_callbacks.printError(message)


class MakePreAnalyzeValidationCommand(object):
    def __init__(self, source_tool):
        self.source_tool = source_tool


class MakePreAnalyzeValidationCommandHandler(object):
    def __init__(self, pre_analyze_validator):
        self._pre_analyze_validator = pre_analyze_validator

    def handle(self, command):
        return self._pre_analyze_validator.validate(command.source_tool)


class MakePreProcessValidationCommand(object):
    def __init__(self, extension, is_in_scope, status_code):
        self.extension = extension
        self.is_in_scope = is_in_scope
        self.status_code = status_code


class MakePreProcessValidationCommandHandler(object):
    def __init__(self, pre_process_validator):
        self._pre_process_validator = pre_process_validator

    def handle(self, command):
        return self._pre_process_validator.validate(
            command.extension,
            command.is_in_scope,
            command.status_code
        )


class HighlightSettings(DomainDict):
    def _get_default_values(self):
        return {
            'highlight_enabled': False,
            'highlight_status': 'New',
            'highlight_color': 'orange',
        }

    def _get_storage_key(self):
        return 'HighlightSettings'


class HighlightPanel(JPanel, ItemListener):
    __metaclass__ = Singleton
    COLORS = ["red", "orange", "yellow", "green", "blue", "pink", "magenta", "gray"]

    def __init__(self):
        super(HighlightPanel, self).__init__()
        self._check_box = None
        self._status_combo = None
        self._color_combo = None

    def display(self, values):
        self._check_box = JCheckBox("Enable highlighting in Proxy history")
        self._check_box.setSelected(values.get('highlight_enabled', False))
        self._check_box.addItemListener(self)

        self._status_combo = JComboBox(Application.ITEM_STATUSES)
        self._status_combo.setSelectedItem(values.get('highlight_status', 'New'))
        self._status_combo.addItemListener(self)

        self._color_combo = JComboBox(self.COLORS)
        self._color_combo.setSelectedItem(values.get('highlight_color', 'orange'))
        self._color_combo.addItemListener(self)

        self.add(self._check_box)
        self.add(JLabel("Status:"))
        self.add(self._status_combo)
        self.add(JLabel("Color:"))
        self.add(self._color_combo)

    def itemStateChanged(self, event):
        source = event.getSource()
        if source == self._check_box:
            Application.get_instance().execute(SetDomainDictValueCommand(
                SetDomainDictValueCommand.TYPE_HIGHLIGHT_SETTINGS,
                'highlight_enabled',
                self._check_box.isSelected()
            ))
        elif source == self._status_combo and event.getStateChange() == ItemEvent.SELECTED:
            Application.get_instance().execute(SetDomainDictValueCommand(
                SetDomainDictValueCommand.TYPE_HIGHLIGHT_SETTINGS,
                'highlight_status',
                self._status_combo.getSelectedItem()
            ))
        elif source == self._color_combo and event.getStateChange() == ItemEvent.SELECTED:
            Application.get_instance().execute(SetDomainDictValueCommand(
                SetDomainDictValueCommand.TYPE_HIGHLIGHT_SETTINGS,
                'highlight_color',
                self._color_combo.getSelectedItem()
            ))


class OptionsPanel(JPanel):
    def __init__(self):
        super(OptionsPanel, self).__init__()
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self._add_label('Database')
        self._add_panel(DatabasePanel())
        self._add_label('Scope tools')
        self._add_panel(ScopeToolsPanel())
        self._add_label('Excluded extensions')
        self._add_panel(ExcludedExtensionsPanel())
        self._add_label('Excluded status codes')
        self._add_panel(ExcludedStatusCodesPanel())
        self._add_label('Misc')
        self._add_panel(OverwriteDuplicateItemsPanel())
        self._add_panel(ProcessOnlyInScopeRequestsPanel())
        self._add_panel(SetInProgressStatusWhenSendingItemToToolPanel())
        self._add_label('Highlighting')
        self._add_panel(HighlightPanel())

    def _add_label(self, label):
        panel = JPanel()
        panel.add(JLabel('<html><h2>%s</h2></html>' % label))
        self._add_panel(panel)

    def _add_panel(self, panel):
        panel.setMaximumSize(panel.getPreferredSize())
        panel.setAlignmentX(Component.LEFT_ALIGNMENT)
        self.add(panel)


class OverwriteDuplicateItemsPanel(CheckBoxPanel):
    def _get_domain_dict_key(self):
        return 'overwrite_duplicate_items'

    def _get_domain_dict_type(self):
        return SetDomainDictValueCommand.TYPE_DUPLICATE_ITEMS

    def _get_label(self):
        return 'Overwrite duplicate items'


class PathPattern(object):
    def __init__(self, id, method, path_regexp, target):
        self._id = id
        self._method = method
        self._path_regexp = path_regexp
        self._path_regexp_compiled = re.compile(path_regexp)
        self._target = target

    def get_id(self):
        return self._id

    def get_method(self):
        return self._method

    def get_path_regexp(self):
        return self._path_regexp

    def get_target(self):
        return self._target

    def set_id(self, id):
        self._id = id

    # business logic
    def get_unique_key(self):
        return self.get_target() + self.get_method() + self.get_path_regexp()

    def is_item_matched(self, item):
        return \
            self._target == item.get_target() and \
            self._method == item.get_method() and \
            self._path_regexp_compiled.match(item.get_path())


class PathPatternRepository(Repository):
    # persistence
    def _create_table(self):
        self._database.execute(
            'CREATE TABLE path_patterns('
            'id INTEGER PRIMARY KEY,
            'method TEXT NOT NULL,
            'path_regexp TEXT NOT NULL,
            'target TEXT NOT NULL,
            'UNIQUE(method, path_regexp, target) ON CONFLICT IGNORE)'
        )

    def _delete_objects(self, ids):
        self._database.delete('DELETE FROM path_patterns WHERE id in (%s)' % ','.join(map(str, ids)))

    def _get_all_objects(self):
        path_patterns = []
        for row in self._database.select(
                'SELECT '
                'id, method, path_regexp, target '
                'FROM path_patterns '
                'ORDER BY id'
        ):
            path_patterns.append(PathPattern(*row))
        return path_patterns

    def _insert_object(self, path_pattern):
        self._database.insert(
            'INSERT INTO '
            'path_patterns(id, method, path_regexp, target) '
            'values(?, ?, ?, ?)',
            (
                path_pattern.get_id(),
                path_pattern.get_method(),
                path_pattern.get_path_regexp(),
                path_pattern.get_target()
            )
        )

    def _update_objects(self, property, value, ids):
        pass


class PathPatternsByItemFilter(object):
    def __init__(self, item):
        self._item = item

    def __call__(self, *args, **kwargs):
        return args[0].is_item_matched(self._item)


class PathPatternsColumnModel(TableColumnModel):
    @staticmethod
    def _prepare_columns():
        return [
            # name, class, is array?, is editable?
            ('Id', Integer, False, False),
            ('Path regexp', String, False, False),
            ('Method', String, False, False),
            ('Target', String, False, False),
        ]


class PathPatternsModel(TableModel):
    @staticmethod
    def _create_column_model():
        return PathPatternsColumnModel()

    @staticmethod
    def _create_set_object_property_application_command(id, property, value):
        pass


class PathPatternsPanel(JScrollPane):
    def __init__(self):
        super(PathPatternsPanel, self).__init__(PathPatternsTable())


class PathPatternsPopupMenu(TablePopupMenu):
    def __init__(self):
        super(PathPatternsPopupMenu, self).__init__()

    @staticmethod
    def _create_application_command(command):
        if command == 'Delete':
            return DeleteSelectedObjectsCommand(DeleteSelectedObjectsCommand.TYPE_PATH_PATTERN)

    @staticmethod
    def _prepare_labels():
        return {
            'Delete': {}
        }


class PathPatternsTable(Table):
    @staticmethod
    def _create_model():
        return PathPatternsModel()

    @staticmethod
    def _create_popup_menu():
        return PathPatternsPopupMenu()

    @staticmethod
    def _get_domain_dict_type():
        return SetDomainDictValueCommand.TYPE_SELECTED_PATH_PATTERNS


class Persistence(DomainDict):
    def __init__(self, database, item_repository, path_pattern_repository, ui_services, value_repository):
        super(Persistence, self).__init__(value_repository)
        self._database = database
        self._repositories = [
            item_repository,
            path_pattern_repository,
        ]
        self._ui_services = ui_services
        self._load()

    # DomainDict
    def _get_default_values(self):
        return {
            'database_path': '',
        }

    # business logic
    def set_value(self, key, value):
        if self._persist(value):
            super(Persistence, self).set_value(key, value)
            return True
        return False

    def _load(self):
        if self._values['database_path']:
            self._database.connect(self._values['database_path'])
            for repository in self._repositories:
                repository.load()

    def _persist(self, database_path):
        if (
            self._is_driver_loaded() and
            self._prepare_database_file(database_path) and
            self._persist_repositories(database_path)
        ):
            return True
        return False

    def _is_driver_loaded(self):
        if not self._database.is_driver_loaded():
            self._ui_services.display_error(
                '%s driver not found (see "Requirements" on https://github.com/dariusztytko/progress-burp)' % self._database.get_driver_name())
            return False
        return True

    def _prepare_database_file(self, database_path):
        try:
            if os.path.exists(database_path):
                if not self._ui_services.confirm('File already exists. Are you sure you want to replace it?'):
                    return False
            with open(database_path, 'ab') as f:
                f.truncate(0)
            return True
        except IOError as e:
            self._ui_services.display_error(str(e))

    def _persist_repositories(self, database_path):
        if self._database.is_connected():
            self._database.disconnect()
        self._database.connect(database_path)
        for repository in self._repositories:
            repository.init_persistence()
        return True


class PreAnalyzeValidator(DomainDictWithLock):
    def __init__(self, value_repository):
        super(PreAnalyzeValidator, self).__init__(value_repository)

    # DomainDict
    def _get_default_values(self):
        return {
            'scope_tools': ['Proxy'],
            'capturing': 'On'
        }

    # business logic
    def validate(self, source_tool):
        with self._lock:
            return \
                self._values['capturing'] == 'On' and \
                source_tool in self._values['scope_tools']


class PreProcessValidator(DomainDictWithLock):
    def __init__(self, value_repository):
        super(PreProcessValidator, self).__init__(value_repository)

    # DomainDict
    def _get_default_values(self):
        return {
            'excluded_extensions': ['css', 'js', 'gif', 'ico', 'jpg', 'jpeg', 'png', 'svg', 'woff', 'woff2'],
            'excluded_status_codes': ['404'],
            'process_only_in_scope_requests': True,
        }

    # business logic
    def validate(self, extension, is_in_scope, status_code):
        with self._lock:
            return \
                self._validate_extension(extension) and \
                self._validate_scope(is_in_scope) and \
                self._validate_status_code(status_code)

    def _validate_extension(self, extension):
        return extension not in self._values['excluded_extensions']

    def _validate_scope(self, is_in_scope):
        if self._values['process_only_in_scope_requests']:
            return is_in_scope
        return True

    def _validate_status_code(self, status_code):
        return status_code not in self._values['excluded_status_codes']


class ProcessHttpDialogCommand(object):
    def __init__(self, method, request, response, time, tool, url, path):
        self.method = method
        self.request = request
        self.response = response
        self.time = time
        self.tool = tool
        self.url = url
        self.path = path


class ProcessHttpDialogCommandHandler(object):
    def __init__(self, duplicate_items, visible_items):
        self._duplicate_items = duplicate_items
        self._visible_items = visible_items

    def handle(self, command):
        self._duplicate_items.add_item(
            self._create_item(command)
        )
        self._visible_items.display()

    def _create_item(self, command):
        return Item(
            '',
            command.url.getHost(),
            None,
            command.method,
            command.path,
            command.url.getPort(),
            command.url.getProtocol(),
            command.request,
            command.response,
            'New',
            [],
            command.time,
            command.tool
        )


class ProcessOnlyInScopeRequestsPanel(CheckBoxPanel):
    def _get_domain_dict_key(self):
        return 'process_only_in_scope_requests'

    def _get_domain_dict_type(self):
        return SetDomainDictValueCommand.TYPE_PRE_PROCESS_VALIDATOR

    def _get_label(self):
        return 'Process only in-scope requests'


class ProgressTab(ITab):
    def __init__(self):
        self._ui_component = JTabbedPane()
        self._ui_component.addTab('Items', ItemsPanel())
        self._ui_component.addTab('Path patterns', PathPatternsPanel())
        self._ui_component.addTab('Options', JScrollPane(OptionsPanel()))
        BurpCallbacks.get_instance().customizeUiComponent(self._ui_component)

    def getTabCaption(self):
        return 'Progress'

    def getUiComponent(self):
        return self._ui_component


class ScopeToolsPanel(JPanel, ItemListener):
    __metaclass__ = Singleton

    def __init__(self):
        super(ScopeToolsPanel, self).__init__()
        self._check_boxes = []

    def itemStateChanged(self, event):
        scope_tools = []
        for check_box in self._check_boxes:
            if check_box.isSelected():
                scope_tools.append(check_box.getLabel())
        Application.get_instance().execute(SetDomainDictValueCommand(
            SetDomainDictValueCommand.TYPE_PRE_ANALYZE_VALIDATOR,
            'scope_tools',
            scope_tools
        ))

    def display(self, active_scope_tools):
        self._prepare_components(active_scope_tools)

    def _prepare_components(self, values):
        for scope_tool in Application.SCOPE_TOOLS:
            check_box = JCheckBox(scope_tool)
            check_box.setSelected(scope_tool in values['scope_tools'])
            check_box.addItemListener(self)
            self._check_boxes.append(check_box)
            self.add(check_box)


class SelectedItems(SelectedObjects):
    def __init__(self, burp_services, item_repository, ui_services, value_repository):
        super(SelectedItems, self).__init__(item_repository, ui_services, value_repository)
        self._burp_services = burp_services
        self._item_repository = item_repository
        self._ui_services = ui_services

    # DomainDict
    def _get_default_values(self):
        default_values = super(SelectedItems, self)._get_default_values()
        default_values.update({
            'set_in_progress_status_when_sending_item_to_tool': True,
        })
        return default_values

    # business logic
    def set_value(self, key, value):
        super(SelectedItems, self).set_value(key, value)
        if key == 'main_object_id':
            self._display_main_selected_item()

    def create_path_pattern_from_main_selected_item(self):
        main_selected_item = self._find_main_selected_item()
        return self._create_path_pattern(main_selected_item), main_selected_item

    def send_selected_items_to_tool(self, tool_name):
        self._burp_services.send_items_to_tool(self._find_selected_items(), tool_name)
        if self._values['set_in_progress_status_when_sending_item_to_tool']:
            self.set_selected_item_properties('status', 'In progress')

    def set_selected_item_properties(self, property, value):
        if value is None:
            value = self._ask_for_property(property)
        if value is not None:
            self._item_repository.update_property_by_ids(property, value, self._values['object_ids'])

    def _ask_for_path_regexp(self, path):
        path_regexp = self._ui_services.ask_for_value(
            'Path pattern',
            r'Enter path regexp (e.g. /article/\d+/comments)',
            path,
            False
        )
        if path_regexp:
            try:
                re.compile(path_regexp)
                return path_regexp
            except re.error:
                self._ui_services.display_error('Invalid regular expression')

    def _ask_for_property(self, property):
        title = property.title()
        message = 'Enter %s' % property
        is_value_array = False
        if property == 'tags':
            message = 'Enter comma separated tags (e.g. auth,registration)'
            is_value_array = True
        return self._ui_services.ask_for_value(
            title,
            message,
            self._get_main_selected_item_property(property),
            is_value_array
        )

    def _create_path_pattern(self, main_selected_item):
        if main_selected_item:
            path_regexp = self._ask_for_path_regexp(main_selected_item.get_path())
            if path_regexp:
                return PathPattern(
                    None,
                    main_selected_item.get_method(),
                    path_regexp,
                    main_selected_item.get_target()
                )

    def _display_main_selected_item(self):
        self._ui_services.display_http_dialog(
            self._find_main_selected_item()
        )

    def _find_main_selected_item(self):
        if self._values['main_object_id']:
            return self._item_repository.find_by_id(self._values['main_object_id'])

    def _find_selected_items(self):
        return self._item_repository.find_by_ids(self._values['object_ids'])

    def _get_main_selected_item_property(self, property):
        main_selected_item = self._find_main_selected_item()
        if main_selected_item:
            value = getattr(main_selected_item, 'get_%s' % property)()
            if isinstance(value, list):
                return InfrastructureHelpers.join(value)
            return value

    def _get_object_plural_name(self):
        return 'items'


class SelectedPathPatterns(SelectedObjects):
    def __init__(self, path_pattern_repository, ui_services, value_repository):
        super(SelectedPathPatterns, self).__init__(path_pattern_repository, ui_services, value_repository)

    def _get_object_plural_name(self):
        return 'path patterns'


class SendSelectedItemsToToolCommand(object):
    def __init__(self, tool_name):
        self.tool_name = tool_name


class SendSelectedItemsToToolCommandHandler(object):
    def __init__(self, selected_items, visible_items):
        self._selected_items = selected_items
        self._visible_items = visible_items

    def handle(self, command):
        self._selected_items.send_selected_items_to_tool(command.tool_name)
        self._visible_items.display()


class SetDomainDictValueCommand(object):
    TYPE_DUPLICATE_ITEMS = 1
    TYPE_PERSISTENCE = 2
    TYPE_PRE_ANALYZE_VALIDATOR = 3
    TYPE_PRE_PROCESS_VALIDATOR = 4
    TYPE_SELECTED_ITEMS = 5
    TYPE_SELECTED_PATH_PATTERNS = 6
    TYPE_VISIBLE_ITEMS = 7
    TYPE_HIGHLIGHT_SETTINGS = 8

    def __init__(self, type, key, value):
        self.type = type
        self.key = key
        self.value = value


class SetDomainDictValueCommandHandler(object):
    def __init__(
        self,
        duplicate_items,
        highlight_settings,
        persistence,
        pre_analyze_validator,
        pre_process_validator,
        selected_items,
        selected_path_patterns,
        visible_items
    ):
        self._domain_dict_handlers = {
            SetDomainDictValueCommand.TYPE_DUPLICATE_ITEMS: duplicate_items,
            SetDomainDictValueCommand.TYPE_HIGHLIGHT_SETTINGS: highlight_settings,
            SetDomainDictValueCommand.TYPE_PERSISTENCE: persistence,
            SetDomainDictValueCommand.TYPE_PRE_ANALYZE_VALIDATOR: pre_analyze_validator,
            SetDomainDictValueCommand.TYPE_PRE_PROCESS_VALIDATOR: pre_process_validator,
            SetDomainDictValueCommand.TYPE_SELECTED_ITEMS: selected_items,
            SetDomainDictValueCommand.TYPE_SELECTED_PATH_PATTERNS: selected_path_patterns,
            SetDomainDictValueCommand.TYPE_VISIBLE_ITEMS: visible_items,
        }

    def handle(self, command):
        return self._domain_dict_handlers[command.type].set_value(command.key, command.value)


class SetInProgressStatusWhenSendingItemToToolPanel(CheckBoxPanel):
    def _get_domain_dict_key(self):
        return 'set_in_progress_status_when_sending_item_to_tool'

    def _get_domain_dict_type(self):
        return SetDomainDictValueCommand.TYPE_SELECTED_ITEMS

    def _get_label(self):
        return 'Set "In progress" status when sending item to tool'


class SetItemPropertyCommand(object):
    def __init__(self, id, property, value):
        self.id = id
        self.property = property
        self.value = value


class SetItemPropertyCommandHandler(object):
    def __init__(self, item_repository, visible_items):
        self._item_repository = item_repository
        self._visible_items = visible_items

    def handle(self, command):
        self._item_repository.update_property_by_id(command.property, command.value, command.id)
        self._visible_items.display()


class SetSelectedItemPropertiesCommand(object):
    def __init__(self, property, value):
        self.property = property
        self.value = value


class SetSelectedItemPropertiesCommandHandler(object):
    def __init__(self, selected_items, visible_items):
        self._selected_items = selected_items
        self._visible_items = visible_items

    def handle(self, command):
        self._selected_items.set_selected_item_properties(command.property, command.value)
        self._visible_items.display()


class StatusCellRenderer(DefaultTableCellRenderer):
    COLORS = {
        'Blocked': Color(255, 192, 203),
        'Done': Color(144, 238, 144),
        'Ignored': Color.LIGHT_GRAY,
        'In progress': Color(255, 255, 224),
        'New': Color.WHITE,
        'Postponed': Color(135, 206, 250),
    }

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        component = super(StatusCellRenderer, self).getTableCellRendererComponent(
            table,
            value,
            is_selected,
            has_focus,
            row,
            column
        )
        component.setBackground(self.COLORS[value])
        return component


class StatusPanel(JPanel, ItemListener):
    __metaclass__ = Singleton

    def __init__(self):
        super(StatusPanel, self).__init__()
        self._check_boxes = []

    def itemStateChanged(self, event):
        statuses = []
        for check_box in self._check_boxes:
            if check_box.isSelected():
                statuses.append(check_box.getLabel())
        Application.get_instance().execute(SetDomainDictValueCommand(
            SetDomainDictValueCommand.TYPE_VISIBLE_ITEMS,
            'statuses',
            statuses
        ))

    def display(self, values):
        self.add(JLabel('<html><b>Statuses:</b></html>'))
        for status in Application.ITEM_STATUSES:
            check_box = JCheckBox(status)
            check_box.setSelected(status in values['statuses'])
            check_box.addItemListener(self)
            self._check_boxes.append(check_box)
            self.add(check_box)


class TagOperatorPanel(JPanel, ItemListener):
    __metaclass__ = Singleton

    _OPTIONS = ['OR', 'AND']

    def __init__(self):
        super(TagOperatorPanel, self).__init__()
        self._buttons = []

    def display(self, values):
        self.add(JLabel('<html><b>Tag operator:</b></html>'))
        button_group = ButtonGroup()
        for option in self._OPTIONS:
            button = JRadioButton(option)
            button.setSelected(option == values['tag_operator'])
            button.addItemListener(self)
            button_group.add(button)
            self._buttons.append(button)
            self.add(button)

    def itemStateChanged(self, event):
        for button in self._buttons:
            if button.isSelected():
                Application.get_instance().execute(SetDomainDictValueCommand(
                    SetDomainDictValueCommand.TYPE_VISIBLE_ITEMS,
                    'tag_operator',
                    button.getLabel()
                ))
                break


class TagPanel(JPanel, FocusListener):
    __metaclass__ = Singleton

    def __init__(self):
        super(TagPanel, self).__init__()
        self._text_field = None

    def focusGained(self, event):
        pass

    def focusLost(self, event):
        Application.get_instance().execute(SetDomainDictValueCommand(
            SetDomainDictValueCommand.TYPE_VISIBLE_ITEMS,
            'tags',
            InfrastructureHelpers.split(self._text_field.getText())
        ))

    def display(self, values):
        self.add(JLabel('<html><b>Tags:</b></html>'))
        self._prepare_components(values)

    def _prepare_components(self, values):
        self._text_field = JTextField()
        self._text_field.setColumns(30)
        self._text_field.setEditable(True)
        self._text_field.setText(InfrastructureHelpers.join(values['tags']))
        self._text_field.addFocusListener(self)
        self.add(self._text_field)


class UIHelpers(object):
    @staticmethod
    def ask_for_value(title, message, value, is_value_array):
        new_value = JOptionPane.showInputDialog(
            Frame(),
            message,
            title,
            JOptionPane.PLAIN_MESSAGE,
            None,
            None,
            value
        )
        if new_value is not None:
            if is_value_array:
                return InfrastructureHelpers.split(new_value)
            return new_value

    @staticmethod
    def choose_file():
        chooser = JFileChooser()
        if chooser.showSaveDialog(Frame()) == JFileChooser.APPROVE_OPTION:
            return chooser.getSelectedFile().getCanonicalPath()

    @staticmethod
    def confirm(message):
        return JOptionPane.showConfirmDialog(
            Frame(),
            message,
            'Confirmation',
            JOptionPane.YES_NO_OPTION
        ) == JOptionPane.YES_OPTION

    @staticmethod
    def display_error(message):
        JOptionPane.showMessageDialog(
            Frame(),
            message,
            'Error',
            JOptionPane.ERROR_MESSAGE
        )


class UIServices(object):
    def __init__(self):
        self._panels = [
            CapturingPanel(),
            DatabasePanel(),
            ExcludedExtensionsPanel(),
            ExcludedStatusCodesPanel(),
            HighlightPanel(),
            OverwriteDuplicateItemsPanel(),
            ProcessOnlyInScopeRequestsPanel(),
            ScopeToolsPanel(),
            SetInProgressStatusWhenSendingItemToToolPanel(),
            StatusPanel(),
            TagOperatorPanel(),
            TagPanel(),
        ]
        self._tables = {
            'Items': ItemsTable(),
            'PathPatterns': PathPatternsTable(),
        }

    def ask_for_value(self, title, message, value, is_value_array):
        return UIHelpers.ask_for_value(title, message, value, is_value_array)

    def confirm(self, message):
        return UIHelpers.confirm(message)

    def display_error(self, message):
        UIHelpers.display_error(message)

    def display_http_dialog(self, item):
        HttpDialogEditor().display(item)

    def display_objects(self, type, objects):
        self._tables[type].getModel().display(objects)

    def display_panels(self, values):
        for panel in self._panels:
            panel.display(values)


class ValueRepository(object):
    __metaclass__ = Singleton

    def __init__(self):
        self._burp_callbacks = BurpCallbacks.get_instance()

    def get(self, key, default_value):
        value = self._burp_callbacks.loadExtensionSetting(key)
        if value is None:
            return default_value
        return json.loads(value)

    def set(self, key, value):
        self._burp_callbacks.saveExtensionSetting(key, json.dumps(value))


class VisibleItems(VisibleObjects):
    def __init__(self, item_repository, ui_services, value_repository):
        super(VisibleItems, self).__init__(item_repository, ui_services, value_repository)

    # VisibleObjects
    def _get_default_values(self):
        return {
            'statuses': Application.ITEM_STATUSES,
            'tags': [],
            'tag_operator': 'OR',
        }

    def _get_filters(self):
        filters = [
            ItemsByStatusesFilter(self._values['statuses'])
        ]
        if self._values['tags']:
            filters.append(ItemsByTagsFilter(self._values['tags'], self._values['tag_operator']))
        return filters

    def _get_object_type(self):
        return 'Items'


class VisiblePathPatterns(VisibleObjects):
    def __init__(self, path_pattern_repository, ui_services, value_repository):
        super(VisiblePathPatterns, self).__init__(path_pattern_repository, ui_services, value_repository)

    # VisibleObjects
    def _get_filters(self):
        return []

    def _get_object_type(self):
        return 'PathPatterns'
