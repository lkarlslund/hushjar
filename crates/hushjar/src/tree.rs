//! Builds the left-hand tree from the accounts, then flattens it into the
//! visible rows for the current grouping, filter and expanded branches.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::mock::{Account, Item, ItemType};
use crate::{RowIcon, RowKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    Folders,
    Collections,
    Types,
}

impl GroupBy {
    pub fn from_index(index: i32) -> Self {
        match index {
            1 => GroupBy::Collections,
            2 => GroupBy::Types,
            _ => GroupBy::Folders,
        }
    }

    pub fn index(self) -> i32 {
        match self {
            GroupBy::Folders => 0,
            GroupBy::Collections => 1,
            GroupBy::Types => 2,
        }
    }
}

/// One visible row.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub key: String,
    pub kind: RowKind,
    pub icon: RowIcon,
    pub depth: usize,
    pub label: String,
    pub detail: String,
    pub count: usize,
    pub expandable: bool,
    pub expanded: bool,
    pub locked: bool,
    pub account: usize,
    pub item: Option<String>,
    /// Where this row sits, for headers: "sam@example.org › Work".
    pub path: String,
    /// For folder rows, the Bitwarden folder ID; used to file new items.
    pub folder: Option<String>,
}

pub struct Tree {
    pub rows: Vec<Row>,
    /// Distinct items that match the filter, across all accounts.
    pub matches: usize,
}

struct Node {
    row: Row,
    children: Vec<Node>,
}

impl Node {
    fn group(
        account: usize,
        key: String,
        icon: RowIcon,
        label: &str,
        path: &str,
        children: Vec<Node>,
    ) -> Self {
        let count = children.iter().map(Node::leaves).sum();
        Node {
            row: Row {
                key,
                kind: RowKind::Group,
                icon,
                depth: 0,
                label: label.into(),
                detail: String::new(),
                count,
                expandable: false,
                expanded: false,
                locked: false,
                account,
                item: None,
                path: path.into(),
                folder: None,
            },
            children,
        }
    }

    fn leaves(&self) -> usize {
        if self.row.kind == RowKind::Item {
            1
        } else {
            self.children.iter().map(Node::leaves).sum()
        }
    }
}

struct Ctx<'a> {
    index: usize,
    account: &'a Account,
    needle: &'a str,
    filtering: bool,
}

impl Ctx<'_> {
    fn visible(&self, item: &Item) -> bool {
        item.matches(self.needle)
    }

    fn leaf(&self, parent: &str, item: &Item, path: &str) -> Node {
        Node {
            row: Row {
                key: format!("{parent}/i/{}", item.id),
                kind: RowKind::Item,
                icon: item.kind.icon(),
                depth: 0,
                label: item.name.clone(),
                detail: item.subtitle(),
                count: 0,
                expandable: false,
                expanded: false,
                locked: false,
                account: self.index,
                item: Some(item.id.clone()),
                path: path.into(),
                folder: item.folder.clone(),
            },
            children: vec![],
        }
    }

    fn leaves<'i>(
        &self,
        parent: &str,
        path: &str,
        items: impl Iterator<Item = &'i Item>,
    ) -> Vec<Node> {
        let mut items: Vec<&Item> = items.filter(|i| self.visible(i)).collect();
        items.sort_by_key(|i| i.name.to_lowercase());
        items
            .into_iter()
            .map(|i| self.leaf(parent, i, path))
            .collect()
    }

    /// Active items: not deleted and not archived.
    fn active(&self) -> impl Iterator<Item = &Item> {
        self.account
            .items
            .iter()
            .filter(|i| !i.deleted && !i.archived)
    }

    /// Adds a group if it has children, or always when `keep_empty` is set
    /// and no filter is active.
    fn push_group(&self, out: &mut Vec<Node>, node: Node, keep_empty: bool) {
        if !node.children.is_empty() || (keep_empty && !self.filtering) {
            out.push(node);
        }
    }

    fn account_node(&self, group_by: GroupBy) -> Node {
        let a = self.account;
        let key = a.id.clone();
        let mut children = Vec::new();
        if !a.locked {
            let base = a.email.as_str();
            if !self.filtering {
                let favs = self.leaves(
                    &format!("{key}/fav"),
                    base,
                    self.active().filter(|i| i.favorite),
                );
                self.push_group(
                    &mut children,
                    Node::group(
                        self.index,
                        format!("{key}/fav"),
                        RowIcon::Favorites,
                        "Favorites",
                        base,
                        favs,
                    ),
                    false,
                );
            }
            match group_by {
                GroupBy::Folders => self.folder_groups(&mut children),
                GroupBy::Collections => self.collection_groups(&mut children),
                GroupBy::Types => self.type_groups(&mut children),
            }
            let archived = self.leaves(
                &format!("{key}/archive"),
                base,
                a.items.iter().filter(|i| i.archived && !i.deleted),
            );
            self.push_group(
                &mut children,
                Node::group(
                    self.index,
                    format!("{key}/archive"),
                    RowIcon::Archive,
                    "Archive",
                    base,
                    archived,
                ),
                false,
            );
            let trash = self.leaves(
                &format!("{key}/trash"),
                base,
                a.items.iter().filter(|i| i.deleted),
            );
            self.push_group(
                &mut children,
                Node::group(
                    self.index,
                    format!("{key}/trash"),
                    RowIcon::Trash,
                    "Trash",
                    base,
                    trash,
                ),
                false,
            );
        }
        let count = if a.locked {
            0
        } else {
            a.items.iter().filter(|i| !i.deleted).count()
        };
        Node {
            row: Row {
                key,
                kind: RowKind::Account,
                icon: RowIcon::Account,
                depth: 0,
                label: a.email.clone(),
                detail: a.server.clone(),
                count,
                expandable: false,
                expanded: false,
                locked: a.locked,
                account: self.index,
                item: None,
                path: a.server.clone(),
                folder: None,
            },
            children,
        }
    }

    fn folder_groups(&self, out: &mut Vec<Node>) {
        let a = self.account;
        // Every folder path plus the parents it implies ("Work/Code" implies "Work").
        let mut paths = BTreeSet::new();
        for folder in &a.folders {
            let mut prefix = String::new();
            for part in folder.name.split('/') {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(part);
                paths.insert(prefix.clone());
            }
        }
        let ids: HashMap<&str, &str> = a
            .folders
            .iter()
            .map(|f| (f.name.as_str(), f.id.as_str()))
            .collect();
        out.extend(self.folder_children("", &paths, &ids));

        let key = format!("{}/nofolder", a.id);
        let loose = self.leaves(&key, &a.email, self.active().filter(|i| i.folder.is_none()));
        self.push_group(
            out,
            Node::group(
                self.index,
                key,
                RowIcon::NoFolder,
                "No folder",
                &a.email,
                loose,
            ),
            false,
        );
    }

    fn folder_children(
        &self,
        parent: &str,
        paths: &BTreeSet<String>,
        ids: &HashMap<&str, &str>,
    ) -> Vec<Node> {
        let a = self.account;
        let mut out = Vec::new();
        for path in paths {
            let (dir, name) = match path.rsplit_once('/') {
                Some((dir, name)) => (dir, name),
                None => ("", path.as_str()),
            };
            if dir != parent {
                continue;
            }
            let key = format!("{}/f/{path}", a.id);
            let crumb = format!("{} › {}", a.email, path.replace('/', " › "));
            let mut children = self.folder_children(path, paths, ids);
            let id = ids.get(path.as_str()).copied();
            if let Some(id) = id {
                children.extend(self.leaves(
                    &key,
                    &crumb,
                    self.active().filter(|i| i.folder.as_deref() == Some(id)),
                ));
            }
            let mut node = Node::group(self.index, key, RowIcon::Folder, name, &crumb, children);
            node.row.folder = id.map(str::to_owned);
            self.push_group(&mut out, node, true);
        }
        out
    }

    fn collection_groups(&self, out: &mut Vec<Node>) {
        let a = self.account;
        let key = format!("{}/my", a.id);
        let mine = self.leaves(
            &key,
            &a.email,
            self.active().filter(|i| i.collections.is_empty()),
        );
        self.push_group(
            out,
            Node::group(
                self.index,
                key,
                RowIcon::MyVault,
                "My vault",
                &a.email,
                mine,
            ),
            true,
        );

        let orgs: BTreeSet<&str> = a
            .collections
            .iter()
            .map(|c| c.organization.as_str())
            .collect();
        for org in orgs {
            let org_path = format!("{} › {org}", a.email);
            let mut collections = Vec::new();
            for c in a.collections.iter().filter(|c| c.organization == org) {
                let key = format!("{}/c/{}", a.id, c.id);
                let path = format!("{org_path} › {}", c.name);
                let items = self.leaves(
                    &key,
                    &path,
                    self.active().filter(|i| i.collections.contains(&c.id)),
                );
                self.push_group(
                    &mut collections,
                    Node::group(self.index, key, RowIcon::Collection, &c.name, &path, items),
                    true,
                );
            }
            let key = format!("{}/o/{org}", a.id);
            self.push_group(
                out,
                Node::group(
                    self.index,
                    key,
                    RowIcon::Organization,
                    org,
                    &org_path,
                    collections,
                ),
                true,
            );
        }
    }

    fn type_groups(&self, out: &mut Vec<Node>) {
        let a = self.account;
        for kind in ItemType::ALL {
            let key = format!("{}/t/{}", a.id, kind.slug());
            let items = self.leaves(&key, &a.email, self.active().filter(|i| i.kind == kind));
            self.push_group(
                out,
                Node::group(
                    self.index,
                    key,
                    kind.icon(),
                    kind.group_label(),
                    &a.email,
                    items,
                ),
                false,
            );
        }
    }
}

fn flatten(
    node: Node,
    depth: usize,
    filtering: bool,
    expanded: &HashSet<String>,
    out: &mut Vec<Row>,
) {
    let mut row = node.row;
    row.depth = depth;
    row.expandable = !node.children.is_empty();
    row.expanded = row.expandable && (filtering || expanded.contains(&row.key));
    let open = row.expanded;
    out.push(row);
    if open {
        for child in node.children {
            flatten(child, depth + 1, filtering, expanded, out);
        }
    }
}

pub fn build(
    accounts: &[Account],
    group_by: GroupBy,
    expanded: &HashSet<String>,
    filter: &str,
) -> Tree {
    let needle = filter.trim().to_lowercase();
    let filtering = !needle.is_empty();
    let mut rows = Vec::new();
    let mut matched = HashSet::new();
    for (index, account) in accounts.iter().enumerate() {
        let ctx = Ctx {
            index,
            account,
            needle: &needle,
            filtering,
        };
        let node = ctx.account_node(group_by);
        if filtering && !account.locked {
            collect_items(&node, &mut matched);
        }
        flatten(node, 0, filtering, expanded, &mut rows);
    }
    Tree {
        rows,
        matches: matched.len(),
    }
}

fn collect_items(node: &Node, out: &mut HashSet<(usize, String)>) {
    if let Some(id) = &node.row.item {
        out.insert((node.row.account, id.clone()));
    }
    for child in &node.children {
        collect_items(child, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::sample;

    fn keys(tree: &Tree) -> Vec<&str> {
        tree.rows.iter().map(|r| r.key.as_str()).collect()
    }

    fn all_expanded(accounts: &[Account], group_by: GroupBy) -> HashSet<String> {
        // Expanding with a filter that matches everything reveals every key.
        let mut set = HashSet::new();
        loop {
            let before = set.len();
            for row in build(accounts, group_by, &set, "").rows {
                if row.expandable {
                    set.insert(row.key);
                }
            }
            if set.len() == before {
                return set;
            }
        }
    }

    #[test]
    fn collapsed_tree_shows_only_accounts() {
        let accounts = sample();
        let tree = build(&accounts, GroupBy::Folders, &HashSet::new(), "");
        assert_eq!(keys(&tree), ["p", "w", "f"]);
        assert!(tree.rows[2].locked);
        assert!(!tree.rows[2].expandable, "a locked account has no children");
    }

    #[test]
    fn nested_folders_follow_slashes() {
        let accounts = sample();
        let expanded = all_expanded(&accounts, GroupBy::Folders);
        let tree = build(&accounts, GroupBy::Folders, &expanded, "");
        let code = tree
            .rows
            .iter()
            .find(|r| r.key == "p/f/Work/Code")
            .expect("nested folder");
        let work = tree
            .rows
            .iter()
            .find(|r| r.key == "p/f/Work")
            .expect("parent folder");
        assert_eq!(code.depth, work.depth + 1);
        assert_eq!(code.label, "Code");
        assert_eq!(code.count, 3);
        assert_eq!(work.count, 4, "parent counts include subfolders");
        assert!(keys(&tree).contains(&"p/f/Work/Code/i/github"));
    }

    #[test]
    fn filter_opens_matching_branches_and_counts_items_once() {
        let accounts = sample();
        let tree = build(&accounts, GroupBy::Folders, &HashSet::new(), "GIT");
        let items: Vec<&str> = tree.rows.iter().filter_map(|r| r.item.as_deref()).collect();
        assert_eq!(items, ["github", "gitlab"]);
        assert_eq!(tree.matches, 2, "the favourite copy is not counted twice");
        assert!(
            tree.rows
                .iter()
                .filter(|r| r.expandable)
                .all(|r| r.expanded)
        );
        assert!(
            keys(&tree).contains(&"f"),
            "locked accounts stay visible while filtering"
        );
    }

    #[test]
    fn filter_never_matches_secret_values() {
        let accounts = sample();
        for secret in ["correct-horse", "4111", "X12345678", "JBSWY3DP"] {
            let tree = build(&accounts, GroupBy::Folders, &HashSet::new(), secret);
            assert_eq!(tree.matches, 0, "{secret} must not be searchable");
        }
    }

    #[test]
    fn filter_matches_websites_and_notes() {
        let accounts = sample();
        assert_eq!(
            build(&accounts, GroupBy::Folders, &HashSet::new(), "bank.example").matches,
            1
        );
        assert_eq!(
            build(&accounts, GroupBy::Folders, &HashSet::new(), "batter").matches,
            1
        );
    }

    #[test]
    fn trash_and_archive_hold_only_their_items() {
        let accounts = sample();
        let expanded = all_expanded(&accounts, GroupBy::Folders);
        let tree = build(&accounts, GroupBy::Folders, &expanded, "");
        let under = |prefix: &str| -> Vec<&str> {
            tree.rows
                .iter()
                .filter(|r| r.key.starts_with(prefix) && r.item.is_some())
                .filter_map(|r| r.item.as_deref())
                .collect()
        };
        assert_eq!(under("p/trash/"), ["forum"]);
        assert_eq!(under("p/archive/"), ["oldphone"]);
        assert!(!under("p/f/").contains(&"forum"));
    }

    #[test]
    fn collections_group_by_organisation() {
        let accounts = sample();
        let expanded = all_expanded(&accounts, GroupBy::Collections);
        let tree = build(&accounts, GroupBy::Collections, &expanded, "");
        let org = tree
            .rows
            .iter()
            .find(|r| r.key == "w/o/Example Ltd")
            .expect("organisation");
        assert_eq!(org.count, 5);
        let mine = tree
            .rows
            .iter()
            .find(|r| r.key == "w/my")
            .expect("my vault");
        assert_eq!(mine.count, 1);
    }

    #[test]
    fn types_cover_every_active_item() {
        let accounts = sample();
        let expanded = all_expanded(&accounts, GroupBy::Types);
        let tree = build(&accounts, GroupBy::Types, &expanded, "");
        let typed: usize = tree
            .rows
            .iter()
            .filter(|r| r.key.starts_with("p/t/") && r.kind == RowKind::Group)
            .map(|r| r.count)
            .sum();
        let active = accounts[0]
            .items
            .iter()
            .filter(|i| !i.deleted && !i.archived)
            .count();
        assert_eq!(typed, active);
    }
}
