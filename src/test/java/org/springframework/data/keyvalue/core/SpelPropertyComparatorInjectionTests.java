/*
 * Copyright 2014-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.data.keyvalue.core;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.Test;

import org.springframework.expression.EvaluationException;
import org.springframework.expression.spel.standard.SpelExpressionParser;

/**
 * Regression tests for CVE-2026-41719 at the 2.7.18 baseline.
 *
 * <p>{@link SpelPropertyComparator} interpolates the caller-supplied sort path straight into a
 * SpEL expression. At this baseline that expression was additionally evaluated against the
 * parser's DEFAULT evaluation context, a {@code StandardEvaluationContext}, which permits type
 * references, constructor calls and arbitrary method invocation. A {@code Sort} property taken
 * from user input therefore reached a full SpEL evaluator. After the fix the expression is
 * evaluated with {@code SimpleEvaluationContext.forReadOnlyDataBinding()}, which allows property
 * reads and nothing else.
 *
 * @see <a href="https://spring.io/security/cve-2026-41719">CVE-2026-41719</a>
 */
class SpelPropertyComparatorInjectionTests {

	static class Person {

		private final String name;

		Person(String name) {
			this.name = name;
		}

		public String getName() {
			return this.name;
		}
	}

	private int compareWithPath(String path) {
		SpelPropertyComparator<Person> comparator = new SpelPropertyComparator<>(path, new SpelExpressionParser());
		return comparator.compare(new Person("alice"), new Person("bob"));
	}

	@Test // CVE-2026-41719
	void sortPathCannotInvokeMethods() {
		assertThatExceptionOfType(EvaluationException.class).isThrownBy(() -> compareWithPath("name.toUpperCase()"));
	}

	@Test // CVE-2026-41719
	void sortPathCannotReferenceTypes() {
		// Deliberately dot-free: the comparator rewrites every "." in the path to "?.", which
		// turns a qualified name like T(java.lang.System) into T(java?.lang?.System) and makes it
		// a PARSE error rather than a demonstration of what the evaluator permits. An unqualified
		// type reference survives that rewrite, so this reaches the evaluation context and shows
		// whether type references are allowed there.
		assertThatExceptionOfType(EvaluationException.class).isThrownBy(() -> compareWithPath("name + T(String)"));
	}

	@Test
	void ordinaryPropertyPathsStillSort() {
		assertThat(compareWithPath("name")).isLessThan(0);
	}

}
