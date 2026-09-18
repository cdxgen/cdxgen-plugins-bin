// P23 §1, R140: the config table used to keep the FIRST reader's value in
// sorted-path order when two files disagreed about a key, and publish it as
// a confident `resolution=config` service. The `const val` tables in this
// same repo have always REFUSED an ambiguous name rather than guess one —
// two tables answering "what constant does this name hold", one refusing
// and one picking by filename (P22's rule).
//
// This fixture holds all three cases at once, so the distinction is a
// corpus fact and not a unit-test one:
//
//  - `unique.host` is set once            -> resolves;
//  - `agreed.host` is set twice, SAME     -> resolves (repetition is not
//                                            disagreement);
//  - `ambiguous.host` is set twice, apart -> UNRESOLVED.
//
// Restoring the defect publishes `module-b.example.com` as a resolved
// service — measured, not predicted: the walk's sort puts moduleb's file
// first, which is precisely why the want-not names BOTH candidates. A
// want-not on the one you expect lets a change in file ordering turn the
// defect green by picking the other.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want service protocol=https name=~unique.example.com resolution=config mode=resolved
// kosi:want service protocol=https name=~agreed.example.com resolution=config mode=resolved
// kosi:want-not service protocol=https name=~module-a.example.com mode=resolved
// kosi:want-not service protocol=https name=~module-b.example.com mode=resolved
package fixtures.ambiguous

import java.net.URL
import java.util.Properties

fun uniqueUrl(props: Properties): URL = URL(props.getProperty("unique.host"))

fun agreedUrl(props: Properties): URL = URL(props.getProperty("agreed.host"))

fun ambiguousUrl(props: Properties): URL = URL(props.getProperty("ambiguous.host"))
