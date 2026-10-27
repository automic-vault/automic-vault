const SKILLS: [(&str, &str); 2] = [
    (
        "blessed-script",
        include_str!("../skills/blessed-script/SKILL.md"),
    ),
    (
        "reentrant-blessed-script",
        include_str!("../skills/reentrant-blessed-script/SKILL.md"),
    ),
];
const SKILLS_README: &str = include_str!("../skills/README.md");

fn frontmatter_value<'a>(skill: &'a str, key: &str) -> Option<&'a str> {
    let rest = skill.strip_prefix("---\n")?;
    let (frontmatter, _) = rest.split_once("\n---\n")?;
    frontmatter
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(": "))
}

fn sh_blocks(skill: &str) -> Vec<Vec<&str>> {
    let mut blocks = Vec::new();
    let mut lines = skill.lines();
    while lines.any(|line| line == "```sh") {
        blocks.push(lines.by_ref().take_while(|line| *line != "```").collect());
    }
    blocks
}

// Mirrors the line-exact manifest grammar in
// src/menu-helper/Sources/MenubarHelperCore/BlessedScripts.swift.
fn assert_script_declaration(block: &[&str]) {
    let shebang = block[0];
    assert!(shebang.contains(" -- /"), "{shebang}");
    assert_eq!(block.get(1), Some(&"# --- automic-vault"));
    match block.get(2) {
        Some(&"# capabilities: {}") | Some(&"# capabilities: { inherit: true }") => {
            assert_eq!(block.get(3), Some(&"# ---"));
        }
        Some(&"# capabilities:") => {
            let end = block.iter().position(|line| *line == "# ---").unwrap();
            assert!(end > 3, "missing capabilities");
            for line in &block[3..end] {
                let (gate, level) = line.strip_prefix("#   ").unwrap().split_once(": ").unwrap();
                assert!(
                    gate.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                    "{line}"
                );
                assert!(
                    [
                        "read-only",
                        "local-write",
                        "read-and-updates",
                        "write",
                        "trusted",
                        "full"
                    ]
                    .contains(&level),
                    "{line}"
                );
            }
        }
        other => panic!("expected `# capabilities:`, found {other:?}"),
    }
}

#[test]
fn agent_skills_have_valid_frontmatter() {
    for (directory, skill) in SKILLS {
        assert_eq!(frontmatter_value(skill, "name"), Some(directory));
        let description = frontmatter_value(skill, "description").unwrap();
        assert!(!description.is_empty() && description.len() <= 1024);
        assert!(SKILLS_README.contains(&format!("({directory}/SKILL.md)")));
    }
}

#[test]
fn agent_skill_script_declarations_use_the_manifest_grammar() {
    let mut declarations = 0;
    for (_, skill) in SKILLS {
        for block in sh_blocks(skill) {
            if block
                .first()
                .is_some_and(|line| line.starts_with("#!/usr/local/bin/av inject "))
            {
                assert_script_declaration(&block);
                declarations += 1;
            }
        }
    }
    assert_eq!(declarations, 2);
}
